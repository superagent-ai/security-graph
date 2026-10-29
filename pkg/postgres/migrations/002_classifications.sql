-- Classifications belong to the same organization and asset as their finding.
-- Catalog definitions are immutable engine data; no tenant-global rows are added.
ALTER TABLE security_graph.entities DROP CONSTRAINT entities_kind_check;
ALTER TABLE security_graph.entities ADD CONSTRAINT entities_kind_check
  CHECK (kind IN ('asset','report','finding','relationship','classification'));
CREATE INDEX classifications_types ON security_graph.entities USING gin ((data->'target_ids')) WHERE kind='classification';
