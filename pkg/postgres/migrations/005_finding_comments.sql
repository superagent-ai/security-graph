ALTER TABLE security_graph.entities DROP CONSTRAINT entities_kind_check;
ALTER TABLE security_graph.entities ADD CONSTRAINT entities_kind_check
  CHECK (kind IN ('asset','report','finding','relationship','classification','comment'));
CREATE INDEX entities_finding_comments ON security_graph.entities
  (organization_id,(data->>'finding_id'),created_at DESC,id DESC) WHERE kind='comment';
