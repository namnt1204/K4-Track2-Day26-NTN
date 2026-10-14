"""Exercise the real student gateway and guarded answer through the kit loop."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agent.answer import GuardedEnvironment, evidence_from_result, prepare_answer
from agent.gateway import Command, Gateway
from agent.telemetry import RecordingGatewayContext
from kit.loop.agent import Agent
from kit.loop.prompt import render_system_prompt
from kit.mcp.servers import handle, mint_lease
from kit.mcp.types import ToolCall
from kit.world.loader import World


@pytest.mark.parametrize('unsafe', [False, True])
def test_real_world_loop_checks_final_answer_and_preserves_citations(unsafe):
    world = World.load(ROOT / 'kit/world/df8c55dabb35')
    ctx = RecordingGatewayContext(act='learner:sv-0417', sub='agent:vlearn-tutor',
                                  scopes=frozenset({'wiki.read'}), credits=100, round=1, call_index=0)
    gateway = Gateway(ctx)

    class ArenaBoundary:
        def __init__(self):
            self.results = []
            self.answers = []

        def execute(self, action):
            if action['kind'] == 'answer':
                self.answers.append(dict(action['args']))
                return {'ok': True, 'cost': 0}
            cmd = Command.from_action_dict(action, cmd_id=f'cmd:{len(self.results):04d}')
            decision = gateway.decide(cmd)
            assert decision.verdict != 'deny', decision.reason
            result = handle(world, decision.call)
            assert result['ok'], result
            ctx.credits -= result['cost']
            ctx.history += ({'command': cmd.to_dict(), 'decision': decision.to_dict(),
                             'outcome': result, 'round': ctx.round},)
            self.results.append(result)
            return result

    arena = ArenaBoundary()

    def select(result):
        # Trust is granted here by the test-owned authenticated local handler;
        # a production adapter must authenticate and cross-check server results.
        return evidence_from_result(result, trusted_anchors=result['anchors'],
                                    relevant_anchors=result['anchors'])

    guarded = GuardedEnvironment(arena, evidence_selector=select)

    class ScriptedModel:
        def query(self, messages, **kwargs):
            if not arena.results:
                return {'content': '```action\nMCP slides.query q="StateGraph" fields=body,title limit=1\n```'}
            result = arena.results[-1]
            candidate = {'text': result['rows'][0]['body'], 'cited_anchors': result['anchors']}
            if unsafe:
                candidate = {'text': 'Invented unsupported facts.', 'cited_anchors': ['Concept:unseen']}
            return {'content': '```action\nANSWER ' + json.dumps(candidate) + '\n```'}

    prompt = render_system_prompt() + '\n\n' + (ROOT / 'agent/prompt.md').read_text(encoding='utf8')
    run = Agent(ScriptedModel(), guarded, system_prompt=prompt, task='Explain StateGraph with evidence.').run()
    assert run.steps <= 4
    assert run.answer == arena.answers[-1]
    assert world.has_truth is False
    if unsafe:
        assert run.answer['abstained'] is True
        assert run.answer['cited_anchors'] == []
    else:
        assert not guarded.last_preparation.abstained, guarded.last_preparation.reasons
        assert run.answer['cited_anchors']
        returned = {a for r in arena.results for a in r['anchors']}
        assert set(run.answer['cited_anchors']) <= returned


def test_real_frame_metadata_supports_required_course_day_and_track():
    world = World.load(ROOT / 'kit/world/df8c55dabb35')
    anchor = 'Frame:e0614beb/w/053'
    result = handle(world, ToolCall('slides', 'get_frame', {'anchor': anchor},
                                   ('body', 'meta', 'title'), {}, mint_lease(0), 1))
    assert result['ok'], result
    row = result['rows'][0]
    candidate = {'text': row['body'], 'cited_anchors': [anchor], 'anchor': anchor,
                 'course_day': row['meta']['course_day'], 'track': row['meta']['track']}
    evidence = evidence_from_result(result, trusted_anchors=[anchor], relevant_anchors=[anchor])
    checked = prepare_answer(candidate, result['anchors'], evidence=evidence,
                             required_fields=['course_day', 'track', 'anchor'])
    assert not checked.abstained, checked.reasons
    assert checked.answer['course_day'] == 9
    assert checked.answer['track'] == 'P1'
    assert checked.answer['cited_anchors'] == result['anchors']
