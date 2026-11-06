-- Support source lookups for classification adjacency as well as the existing
-- target_ids GIN index. The shared query contract continues to use keyset IDs.
CREATE INDEX classifications_source ON security_graph.entities
  (organization_id, (data->>'source_id'), id) WHERE kind='classification';
