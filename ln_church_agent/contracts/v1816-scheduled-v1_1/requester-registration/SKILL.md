# scheduled_http_get_batch.v1 / definition 1.1.0

This immutable contract accepts economic values supplied by the server. Obtain current offers at `GET /api/bazaar/task-offers/economic-terms/scheduled`. Confirm the complete offered snapshot before signing a registration. Include the `economic_terms` object, opaque `economic_terms_revision`, and this definition in the family-specific request. A stale offer requires reconfirmation; it is not permission to increase a signed amount.

`economic-terms.schema.json` is a closed value schema. Use integer arithmetic, canonical decimal atomic strings, the existing Base USDC network/asset, uint256 bounds, positive safe-integer capacity and bounded plan labels. Labels and revisions are not accepted-value lists or sources of prices. Unknown fields, types, rules and profiles remain unsupported. The server retains its certified admission and budget limits. Reward maximums and costs must agree arithmetically with the saved snapshot.

Persist the successful Claim and its complete saved terms/digest with the Task and execution identity. Evaluate, report, recover and check status against that operation. Current offers and unrelated TaskGet results never replace an old Claim. Missing saved values are an error; do not fill them with zero or today's prices. The definition manifest hashes contract resources only. Updating a sales revision does not regenerate this pack.

Existing timing, participation, authorization, idempotency, quality, rounding, compensation, visibility and refund rules are unchanged. Common envelopes retain their own versions. Family-specific DTOs use this pack's new suffix. Examples and semantic fixtures are illustrative, not economic dispatch constants.

Scheduled keeps ordered bounded GET, the existing intake/admission limits, Base per accepted execution and one Reference qualification. A pre-Claim cancellation refund remains floor(95% of the original registration amount). The public snapshot excludes private endpoint input.

Read the closed registration and wire schemas in this directory. Follow existing owner-authenticated result recovery for an uncertain payment; do not create a fresh payment to retry an already saved operation.
