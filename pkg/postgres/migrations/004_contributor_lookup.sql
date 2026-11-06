-- Exact MCP submitter filters stay within the organization, while ID order
-- supports keyset pages of findings and assessment runs from each source.
CREATE INDEX entities_contributor ON security_graph.entities
  (organization_id, (data->>'source'), kind, id)
  WHERE kind IN ('finding','report');
