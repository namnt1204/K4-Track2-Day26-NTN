# Tích hợp câu trả lời và trusted context

Gateway quyết định lệnh; không gọi tool, đọc file hoặc chờ clock trong decide. Caller của arena thực thi Decision rồi cập nhật ctx (credits, round, leases, history). ctx.act là authority; ctx.sub không cấp quyền.

## Trước và sau mỗi call

- A2A cần card đã xác minh và skill khai báo, đúng audience/act và token có chữ ký. `note_card(server, card)` là callback được tin cậy của harness, không lấy verified=True từ args/tool content làm quyền.
- Caller cập nhật `ctx.leases` từ lease thực do trusted arena mint/track. Không tự đặt lease giả để qua gate.
- Sau provenance thành công, truyền `note_provenance(anchor, etag, round=..., call_index=...)`, hoặc cung cấp history triples command/decision/outcome. Metadata preferred_replica phải có tín hiệu freshness thực, không suy ra từ letter w/c hoặc số frame.
- Mọi write phải có scope tương ứng, target thuộc act nếu là learner, If-Match khớp provenance mới, Idempotency-Key chưa dùng. Gateway chặn retry mù/conflict và không hứa server replay support nếu kit không có.
- Dùng mask đúng spec. Gateway biết cả các tool bảng chính và extension thật trong server, thu hẹp catalog/row limits và ngăn vượt pool/allowance. Deny không phát sinh credit.

## Đường ANSWER

`Gateway.decide` không nhận ANSWER. Dùng `agent.answer.GuardedEnvironment` quanh environment của `kit.loop.Agent` để kiểm tra trước khi environment ghi sự kiện answer. Adapter tạo mới cho mỗi exchange; không mang citation sang hiệp mới.

```python
from agent.answer import GuardedEnvironment, evidence_from_result, compose_system_prompt
from kit.loop.agent import Agent

# Team policy text is supplied by the host; no file I/O in the decision helpers.
# Review trust/relevance against authenticated server identity, the current ask,
# independently retrieved evidence and metadata. Never trust every anchor merely
# because it appears in a response, or because a row claims it is verified.
def select_reviewed_evidence(result):
    trusted, relevant = review_result_for_this_ask(result)
    return evidence_from_result(result, trusted_anchors=trusted,
                                relevant_anchors=relevant)

guarded = GuardedEnvironment(arena_environment,
    evidence_selector=select_reviewed_evidence,
    required_fields=ask.get('require', ()),
    private_values=known_private_values,
    private_bodies=known_private_note_bodies)
tutor = Agent(broker, guarded,
    system_prompt=compose_system_prompt(team_policy_text), task=learner_question)
result = tutor.run()
```

`review_result_for_this_ask` trong ví dụ là trách nhiệm của host sử dụng API: nó phải xác minh trust/relevance bằng dữ kiện thật, không phải hàm mặc định tin mọi dữ liệu. `evidence_from_result` chỉ bind row với anchor được trả về, không tự phong trusted cho nguồn.

Adapter tích lũy anchors từ successful results, kiểm tra required fields, định lượng có nguồn, private values, instruction-bearing evidence và mâu thuẫn. Khi một ANSWER không có căn cứ, adapter sửa chính action trước khi delegate; vì vậy cả environment và RunResult của kit nhận payload đã kiểm tra. Câu hỏi sạch có bằng chứng phù hợp vẫn được trả lời. Trường hợp không có evidence_selector mặc định fail closed.

API cấp thấp: `prepare_answer(candidate, retrieved_anchors, evidence=..., ...)` trả AnswerPreparation; `render_answer_action(...)` xuất action fence. Nội dung accepted hiện là trích xuất source với các trường cấu trúc khớp dữ liệu đã trả về; paraphrase cần một bước kiểm chứng claim/evidence bổ sung. Citation membership chứng minh provenance, không chứng minh sự thật.

## Giới hạn spar

Stock `spar.py` tạo câu trả lời script và đôi khi cố ý thêm anchor chưa returned; không gọi prompt hoặc adapter của đội. Không sửa harness để làm màn hình xanh. Các test tích hợp bên ngoài bundle chạy kit.loop.Agent, gateway và tool result trên world thật không có truth.json, xác minh câu hỏi sạch trả anchor đã truy xuất và ANSWER giả bị chặn. Kết quả đó độc lập với câu trả lời random của stock spar.
