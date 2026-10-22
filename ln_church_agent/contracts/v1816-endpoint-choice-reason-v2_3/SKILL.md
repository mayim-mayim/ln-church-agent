# endpoint_choice_reason.v2 / definition 2.3.0

This immutable contract accepts economic values supplied by the server. Obtain current offers at `GET /api/bazaar/task-offers/economic-terms/choice`. Confirm the complete offered snapshot before signing a registration. Include the `economic_terms` object, opaque `economic_terms_revision`, and this definition in the family-specific request. A stale offer requires reconfirmation; it is not permission to increase a signed amount.

`economic-terms.schema.json` is a closed value schema. Use integer arithmetic, canonical decimal atomic strings, the existing Base USDC network/asset, uint256 bounds, positive safe-integer capacity and bounded plan labels. Labels and revisions are not accepted-value lists or sources of prices. Unknown fields, types, rules and profiles remain unsupported. The server retains its certified admission and budget limits. Reward maximums and costs must agree arithmetically with the saved snapshot.

Persist the successful Claim and its complete saved terms/digest with the Task and execution identity. Evaluate, report, recover and check status against that operation. Current offers and unrelated TaskGet results never replace an old Claim. Missing saved values are an error; do not fill them with zero or today's prices. The definition manifest hashes contract resources only. Updating a sales revision does not regenerate this pack.

Existing timing, participation, authorization, idempotency, quality, rounding, compensation, visibility and refund rules are unchanged. Common envelopes retain their own versions. Family-specific DTOs use this pack's new suffix. Examples and semantic fixtures are illustrative, not economic dispatch constants.

Keep Jev v2_1 and RPAH v2_1, quality cutoff 0.30, full-reward boundary 0.70 and floor atomic rounding. Use policy `endpoint-choice-reason-economics-terms-v1`. Ordinary Choice and the initial Template Task have no Creator entitlement. Template v4 uses consent `survey-template-bundle-terms-v1`; additional Task v3 uses `survey-template-task-terms-v1` and the displayed conditions_ref. Additional Task Creator rights read the original confirmed amount.
