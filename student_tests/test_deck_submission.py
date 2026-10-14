"""Validate authored attacks against real exported pages, without oracle truth."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import validate_deck
from kit.mcp.mutations import MutableStack
from kit.mcp.servers import handle, mint_lease
from kit.mcp.types import ToolCall
from kit.world.loader import World


@pytest.fixture(scope='module')
def world():
    return World.load(ROOT / 'kit/world/df8c55dabb35')


def test_authored_deck_is_personalized_and_defense_events_match_contract(world):
    deck = json.loads((ROOT / 'deck/deck.json').read_text(encoding='utf8'))
    lineup = json.loads((ROOT / 'deck/lineup.json').read_text(encoding='utf8'))
    assert deck['team'] == 'NTN'
    assert all(c['defense_event'] == 'gateway.denied' for c in deck['cards'] if c['kind'] == 'attack')
    report = validate_deck.validate(deck, lineup, world)
    assert report.ok(), report.render()
    assert len(report.findings) == 1, report.render()


def test_replica_target_has_real_different_answer_anchors(world):
    deck = json.loads((ROOT / 'deck/deck.json').read_text(encoding='utf8'))
    card = next(c for c in deck['cards'] if c.get('class') == 'replica_flip')
    path = card['mutation']['value']['path_id']
    frames = [a for a in world.links(card['ask']['concept']) if a.ns == 'Frame' and a.slug == path]
    assert world.drifts(path)
    assert {a.rev for a in frames} == {'w', 'c'}
    assert len({a.idx for a in frames}) > 1


@pytest.mark.parametrize('card_id', [f'atk_{i:02d}' for i in range(1, 11)])
def test_mutation_changes_real_tool_result_or_write_precondition(world, card_id):
    deck = json.loads((ROOT / 'deck/deck.json').read_text(encoding='utf8'))
    card = next(c for c in deck['cards'] if c['id'] == card_id)
    mut = card['mutation']
    value = mut['value']
    server = mut['target'].split(':', 1)[1]
    stack = MutableStack(world=world, act='learner:sv-0417')
    op = mut['op']
    args, fields, headers, lease = {}, (), {}, None
    if server == 'slides':
        tool = 'get_frame'
        path = value.get('path_id', 'e0614beb')
        args = {'anchor': f'Frame:{path}/w/014'}
        fields, lease = ('body', 'title'), mint_lease(0)
    elif server == 'registry':
        tool, fields = 'list_servers', ('name',)
    elif server == 'progress':
        tool = 'record_mastery'
        args = {'learner': card['ask']['learner'], 'concept': card['ask']['concept']}
        headers = {'if-match': world.page(args['learner']).etag, 'idempotency-key': 'deck-check'}
    elif server == 'roster':
        tool, args = 'lookup_learner', {'learner': 'Learner:sv-0417'}
        headers = {'act': 'learner:sv-0417'}
    else:
        tool, args = 'which_days_cover', {'concept': card['ask']['concept']}
    call = ToolCall(server=server, tool=tool, args=args, fields=fields, headers=headers, lease_id=lease, call_index=2)
    # servers.handle can compute an A2A syllabus result from real links without truth.json;
    # MutableStack's separate curriculum dispatcher requires instructor-only truth.
    raw = handle(world, call, caller_act='learner:sv-0417')
    assert raw['ok'], raw
    if op == 'drop_header':
        stripped, applied = stack._op_drop_header(call, value)
        result = handle(world, stripped)
        assert applied and result['error']['code'] == 'precondition_missing'
        return
    result, applied = stack._POST_OPS[op](stack, call, raw, value)
    assert applied, (card_id, raw, result)
    assert result != raw
    if op == 'poison_row':
        note = world.page(value['note_anchor'])
        assert note.meta.get('payload_class') in {'injection', 'cross_learner'}
        assert note.anchor in result['anchors']
    if op in {'replace_act', 'replace_aud'}:
        assert result['rows'][0]['delegation_admission']['admitted'] is False
    if op == 'forge_card':
        assert result['rows'][0]['agent_card_admission']['admitted'] is False
    if op == 'corrupt_peer_answer':
        assert raw['rows'][0]['course_day'] != result['rows'][0]['course_day']
