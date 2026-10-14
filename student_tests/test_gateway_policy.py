import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))
from agent.gateway import Command, Gateway
from agent.telemetry import RecordingGatewayContext
from kit.mcp.a2a import AGENT_CARDS, mint_delegation
from kit.mcp.specs import TOOL_SPECS


def context(**kw):
    data = dict(act='learner:sv-0417', sub='agent:tutor', scopes=frozenset({'wiki.read'}), credits=100, round=1, call_index=0, leases=(), history=())
    data.update(kw)
    return RecordingGatewayContext(**data)


def command(server='slides', tool='query', **kw):
    data = dict(cmd_id='cmd:0', kind='a2a' if server in AGENT_CARDS else 'mcp', raw='', server=server, tool=tool, args={'q': 'mcp'}, fields=(), headers={}, lease_id=None, call_index=0)
    data.update(kw)
    return Command(**data)


def test_clean_explicit_header_and_narrow_read_forward():
    d = Gateway(context()).decide(command('glossary', 'define', args={'term': 'mcp', 'lang': 'en'}, fields=('definition',), headers={'mcp-replica': 'w'}))
    assert d.verdict == 'forward'


def test_route_defaults_to_working_and_marks_rewrite():
    d = Gateway(context()).decide(command())
    assert d.verdict == 'rewrite'
    assert d.call.headers['mcp-replica'] == 'w'


@pytest.mark.parametrize('key', ['route', '_route', 'replica'])
def test_body_cannot_choose_replica(key):
    assert Gateway(context()).decide(command(args={'q': 'mcp', key: 'c'})).verdict == 'deny'


def test_search_rewrites_compatible_payload_mask_to_query():
    d = Gateway(context()).decide(command(tool='search', fields=('anchor', 'snippet', 'title')))
    assert d.verdict == 'rewrite'
    assert d.call.tool == 'query'
    assert d.call.fields == ('body', 'title')


@pytest.mark.parametrize('fields', [('*',), ()])
@pytest.mark.parametrize('server,tool,mask', [('registry', 'list_servers', ('name',)), ('glossary', 'list_terms', ('term',))])
def test_full_catalog_is_narrowed_not_refused(fields, server, tool, mask):
    d = Gateway(context()).decide(command(server, tool, fields=fields, args={}))
    assert d.verdict == 'rewrite'
    assert d.call.fields == mask


def test_unknown_tool_and_illegal_mask_are_free_denials():
    g = Gateway(context())
    assert g.decide(command(tool='not_real')).verdict == 'deny'
    assert g.decide(command(fields=('anchor',))).verdict == 'deny'


def test_lease_uses_live_context_and_never_invents_one():
    ctx = context(leases=('lse_ok',))
    g = Gateway(ctx)
    c = command(tool='get_frame', args={'anchor': 'Frame:abc/w/001'}, lease_id='lse_ok')
    assert g.decide(c).verdict != 'deny'
    ctx.leases = ()
    assert g.decide(c).verdict == 'deny'
    assert g.decide(command(tool='get_frame', args=c.args)).verdict == 'deny'


@pytest.mark.parametrize('target', ['Learner:sv-0392', 'learner:sv-0392', 'sv-0392'])
def test_different_learner_denied_even_when_sub_claims_target(target):
    assert Gateway(context(sub='agent:sv-0392')).decide(command(args={'q': 'mcp', 'learner': target})).verdict == 'deny'


@pytest.mark.parametrize('target', ['Learner:sv-0417', 'learner:sv-0417', 'sv-0417'])
def test_same_learner_forms_are_accepted(target):
    assert Gateway(context()).decide(command(args={'q': 'mcp', 'learner': target})).verdict != 'deny'


def test_write_needs_scope_and_trusted_provenance_not_outgoing_etag_claim():
    c = command('progress', 'record_mastery', args={'anchor': 'Learner:sv-0417', 'concept': 'Concept:mcp'}, headers={'if-match': 'etag1', 'idempotency-key': 'key1'})
    assert Gateway(context()).decide(c).verdict == 'deny'
    g = Gateway(context(scopes=frozenset({'wiki.read', 'wiki.write:progress'})))
    assert g.decide(c).verdict == 'deny'


def test_successful_history_provenance_enables_write_but_never_replay():
    provenance = dict(command={'server': 'registry', 'tool': 'provenance', 'args': {'anchor': 'Learner:sv-0417'}, 'call_index': 0}, decision={'verdict': 'forward'}, outcome={'ok': True, 'etag': 'etag1', 'rows': [{'etag': 'etag1'}]}, round=1)
    ctx = context(scopes=frozenset({'wiki.read', 'wiki.write:progress'}), history=(provenance,))
    g = Gateway(ctx)
    c = command('progress', 'record_mastery', args={'learner': 'sv-0417', 'concept': 'Concept:mcp'}, headers={'if-match': 'etag1', 'idempotency-key': 'key1'}, call_index=1)
    d = g.decide(c)
    assert d.verdict != 'deny'
    assert d.call.args['anchor'] == 'Learner:sv-0417'
    assert g.decide(c).verdict == 'deny'


def test_legacy_callback_admits_clean_spar_peer_but_not_forged_claim():
    g = Gateway(context())
    c = command('curriculum-analyst', 'which_days_cover', args={'concept': 'Concept:mcp', 'learner': 'learner:sv-0417'}, headers={'aud': 'curriculum-analyst'})
    assert g.decide(c).verdict == 'deny'
    g.note_card(c.server, {'verified': True, 'skills': ['which_days_cover']})
    assert g.decide(c).verdict != 'deny'
    assert g.decide(command(c.server, c.tool, args=c.args, headers={'aud': c.server, 'x-card-signature': 'invalid'})).verdict == 'deny'


@pytest.mark.parametrize('bad', ['audience', 'act', 'signature', 'expired'])
def test_signed_delegation_rejects_bad_identity(bad):
    g = Gateway(context())
    g.note_card('curriculum-analyst', AGENT_CARDS['curriculum-analyst'].to_dict())
    token = mint_delegation('learner:sv-0392' if bad == 'act' else 'learner:sv-0417', 'a2a:roster' if bad == 'audience' else 'a2a:curriculum-analyst', ttl=1).to_dict()
    if bad == 'signature':
        token['signature'] = 'f' * 64
    d = g.decide(command('curriculum-analyst', 'which_days_cover', args={'concept': 'Concept:mcp'}, headers={'delegation': token}, call_index=2 if bad == 'expired' else 0))
    assert d.verdict == 'deny'


def test_signed_valid_delegation_and_replay():
    g = Gateway(context())
    token = mint_delegation('learner:sv-0417', 'a2a:curriculum-analyst', ttl=3).to_dict()
    c = command('curriculum-analyst', 'which_days_cover', args={'concept': 'Concept:mcp'}, headers={'delegation': token})
    d = g.decide(c)
    assert d.verdict != 'deny'
    assert g.decide(c).verdict == 'deny'


def test_forged_fingerprint_is_denied_even_on_mcp():
    assert Gateway(context()).decide(command(headers={'x-server-fingerprint': 'unvouched'})).verdict == 'deny'


def test_global_credits_pace_rounds_and_read_live_pool():
    ctx = context(credits=10)
    g = Gateway(ctx)
    assert g.decide(command('labs', 'get_exercise', args={'anchor': 'Lab:mcp'})).verdict == 'deny'
    ctx.round = 10
    assert g.decide(command('labs', 'get_exercise', args={'anchor': 'Lab:mcp'})).verdict != 'deny'
    ctx.credits = 0
    assert g.decide(command('glossary', 'define', args={'term': 'mcp', 'lang': 'en'})).verdict == 'deny'


def test_query_limit_bounds_real_row_cost():
    d = Gateway(context()).decide(command(args={'q': 'mcp', 'limit': 1000}, fields=('body',)))
    assert d.verdict != 'deny'
    assert 1 <= d.call.args['limit'] <= 3


@pytest.mark.parametrize('headers,fields', [({'mcp-replica': []}, ()), ({'aud': {}}, ()), ({}, (None,)), ({1: 'w'}, ())])
def test_malformed_data_denies_without_raising(headers, fields):
    assert Gateway(context()).decide(command(headers=headers, fields=fields)).verdict == 'deny'


def test_read_scope_is_required():
    assert Gateway(context(scopes=frozenset())).decide(command()).verdict == 'deny'


def test_decide_does_not_import_modules(monkeypatch):
    import builtins
    g = Gateway(context())
    def no_import(*a, **kw):
        raise RuntimeError('policy attempted an import')
    with monkeypatch.context() as m:
        m.setattr(builtins, '__import__', no_import)
        d = g.decide(command())
    assert d.verdict != 'deny'


def test_signed_token_cannot_hide_forged_wire_card():
    token = mint_delegation('learner:sv-0417', 'a2a:curriculum-analyst', ttl=3).to_dict()
    forged = AGENT_CARDS['curriculum-analyst'].to_dict()
    forged['skills'] = ['which_days_cover', 'admin']
    c = command('curriculum-analyst', 'which_days_cover', args={'concept': 'Concept:mcp'}, headers={'delegation': token, 'agent-card': forged})
    assert Gateway(context()).decide(c).verdict == 'deny'


def test_provenance_signal_changes_route_but_label_alone_does_not():
    g = Gateway(context())
    g.note_provenance('Frame:abc/w/001', 'etag1', preferred_replica='c')
    d = g.decide(command('registry', 'provenance', args={'anchor': 'Frame:abc/w/001'}, headers={'mcp-replica': 'w'}))
    assert d.call.headers['mcp-replica'] == 'c'
    g2 = Gateway(context())
    g2.note_provenance('Frame:abc/w/001', 'etag1', replica='c')
    assert g2.decide(command('registry', 'provenance', args={'anchor': 'Frame:abc/w/001'})).call.headers['mcp-replica'] == 'w'


def test_stale_round_callback_cannot_authorize_write():
    ctx = context(scopes=frozenset({'wiki.read', 'wiki.write:progress'}))
    g = Gateway(ctx)
    g.note_provenance('Learner:sv-0417', 'etag1')
    ctx.round = 2
    c = command('progress', 'record_mastery', args={'anchor': 'Learner:sv-0417'}, headers={'if-match': 'etag1', 'idempotency-key': 'key2'})
    assert g.decide(c).verdict == 'deny'


def test_conflict_reread_with_same_etag_cannot_retry_write():
    ctx = context(scopes=frozenset({'wiki.read', 'wiki.write:progress'}), history=({'command': {'server': 'progress', 'tool': 'record_mastery', 'args': {'anchor': 'Learner:sv-0417'}, 'headers': {'if-match': 'etag1'}}, 'decision': {'verdict': 'forward'}, 'outcome': {'ok': False, 'error': {'code': 'conflict'}}},))
    g = Gateway(ctx)
    g.note_provenance('Learner:sv-0417', 'etag1', call_index=1)
    c = command('progress', 'record_mastery', args={'anchor': 'Learner:sv-0417'}, headers={'if-match': 'etag1', 'idempotency-key': 'newkey'}, call_index=2)
    assert g.decide(c).verdict == 'deny'


def test_rate_limited_catalog_does_not_repeat_across_rounds():
    ctx = context()
    g = Gateway(ctx)
    assert g.decide(command('registry', 'list_servers', args={}, fields=('name',))).verdict != 'deny'
    ctx.round = 5
    assert g.decide(command('registry', 'list_servers', args={}, fields=('name',))).verdict == 'deny'


def test_learner_alias_cannot_bypass_provenance_privacy():
    c = command('registry', 'provenance', args={'anchor': 'Learner:sv-0392'}, fields=('etag',))
    assert Gateway(context()).decide(c).verdict == 'deny'


def test_explicit_expensive_fields_narrow_before_budget_denial():
    d = Gateway(context(credits=30)).decide(command('labs', 'get_exercise', args={'anchor': 'Lab:mcp'}, fields=('instructions', 'summary')))
    assert d.verdict == 'rewrite'
    assert d.call.fields == ('summary',)


def test_low_pool_default_peer_mask_narrows_to_useful_response():
    token = mint_delegation('learner:sv-0417', 'a2a:curriculum-analyst', ttl=3).to_dict()
    c = command('curriculum-analyst', 'which_days_cover', args={'concept': 'Concept:mcp'}, headers={'delegation': token})
    d = Gateway(context(credits=60)).decide(c)
    assert d.verdict == 'rewrite'
    assert d.call.fields == ('anchor', 'course_day')


def test_route_keeps_revision_addressed_by_exact_anchor():
    ctx = context(leases=('lse_ok',))
    c = command(tool='get_frame', args={'anchor': 'Frame:abc/c/001'}, lease_id='lse_ok', headers={'mcp-replica': 'w'})
    d = Gateway(ctx).decide(c)
    assert d.verdict == 'rewrite'
    assert d.call.headers['mcp-replica'] == 'c'


@pytest.mark.parametrize('server,tool,args,fields', [
    ('registry', 'get_card', {'server': 'slides'}, ('base', 'server', 'tool')),
    ('research', 'get_citation', {'anchor': 'Source:mcp'}, ('anchor', 'url')),
    ('progress', 'get_mastery', {'learner': 'Learner:sv-0417'}, ('learner', 'summary')),
    ('slides', 'list_sections', {'q': 'mcp'}, ('anchor', 'title')),
    ('labs', 'get_readme', {'anchor': 'Lab:mcp'}, ('anchor', 'body')),
])
def test_server_extensions_are_known_clean_tools(server, tool, args, fields):
    d = Gateway(context()).decide(command(server, tool, args=args, fields=fields, headers={'mcp-replica': 'w'}))
    assert d.verdict == 'forward'


def test_extension_write_obeys_provenance_and_scope():
    g = Gateway(context(scopes=frozenset({'wiki.read', 'wiki.write:registry'})))
    g.note_provenance('Frame:abc/w/001', 'etag1')
    c = command('registry', 'pin', args={'anchor': 'Frame:abc/w/001'}, headers={'if-match': 'etag1', 'idempotency-key': 'pin1'})
    assert g.decide(c).verdict != 'deny'


def test_authoritative_history_reconciles_row_cost_reservation():
    ctx = context()
    g = Gateway(ctx)
    c = command(cmd_id='cmd:query', fields=('title',))
    d = g.decide(c)
    ctx.credits = 98
    ctx.history = ({'command': c.to_dict(), 'decision': d.to_dict(), 'outcome': {'ok': True, 'cost': 2}, 'round': 1},)
    assert g.decide(command('labs', 'get_exercise', args={'anchor': 'Lab:mcp'}, cmd_id='cmd:lab')).verdict != 'deny'
    assert g.decide(command('registry', 'provenance', args={'anchor': 'Frame:abc/w/001'}, cmd_id='cmd:prov')).verdict != 'deny'


def test_prior_write_history_consumes_idempotency_key():
    prior = {'command': {'cmd_id': 'old', 'server': 'progress', 'tool': 'record_mastery', 'args': {'anchor': 'Learner:sv-0417'}, 'headers': {'if-match': 'etag0', 'idempotency-key': 'used'}, 'call_index': 0}, 'decision': {'verdict': 'forward'}, 'outcome': {'ok': True}, 'round': 1}
    ctx = context(scopes=frozenset({'wiki.read', 'wiki.write:progress'}), history=(prior,), call_index=1)
    g = Gateway(ctx)
    g.note_provenance('Learner:sv-0417', 'etag1', call_index=1)
    c = command('progress', 'record_mastery', args={'anchor': 'Learner:sv-0417'}, headers={'if-match': 'etag1', 'idempotency-key': 'used'}, call_index=2)
    assert g.decide(c).verdict == 'deny'


def test_undated_old_history_cannot_issue_fresh_write_authority():
    old = {'command': {'server': 'registry', 'tool': 'provenance', 'args': {'anchor': 'Learner:sv-0417'}, 'call_index': 0}, 'decision': {'verdict': 'forward'}, 'outcome': {'ok': True, 'etag': 'old'}}
    ctx = context(round=2, scopes=frozenset({'wiki.read', 'wiki.write:progress'}), history=(old,))
    c = command('progress', 'record_mastery', args={'anchor': 'Learner:sv-0417'}, headers={'if-match': 'old', 'idempotency-key': 'new'}, call_index=1)
    assert Gateway(ctx).decide(c).verdict == 'deny'


def test_roundless_triple_links_to_own_prior_command():
    ctx = context(scopes=frozenset({'wiki.read', 'wiki.write:progress'}))
    g = Gateway(ctx)
    prov = command('registry', 'provenance', args={'anchor': 'Learner:sv-0417'}, cmd_id='cmd:prov')
    d = g.decide(prov)
    ctx.history = ((prov, d, {'ok': True, 'etag': 'etag1'}),)
    c = command('progress', 'record_mastery', args={'anchor': 'Learner:sv-0417'}, headers={'if-match': 'etag1', 'idempotency-key': 'new'}, cmd_id='cmd:write', call_index=1)
    assert g.decide(c).verdict != 'deny'


def test_unqualified_read_uses_policy_heuristic_over_model_replica_guess():
    c = command(headers={'mcp-replica': 'c'})
    d = Gateway(context()).decide(c)
    assert d.verdict == 'rewrite'
    assert d.call.headers['mcp-replica'] == 'w'


def test_action_grammar_decimal_query_limit_becomes_server_integer():
    from kit.loop.agent import canonicalise_action
    c = Command.from_action_dict(canonicalise_action('MCP slides.query q="StateGraph" fields=body,title limit=1', call_index=0), cmd_id='wire:1')
    d = Gateway(context()).decide(c)
    assert d.verdict == 'rewrite'
    assert d.call.args['limit'] == 1


@pytest.mark.parametrize('limit', ['-1', 'true', True, '1.5', 'NaN'])
def test_wire_limit_does_not_accept_invalid_integer(limit):
    assert Gateway(context()).decide(command(args={'q': 'mcp', 'limit': limit})).verdict == 'deny'
