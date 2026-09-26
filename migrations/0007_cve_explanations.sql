-- One stored Gemini reply per CVE. A later page view does not call the API again.

CREATE TABLE cve_explanations (
    cve_id UUID PRIMARY KEY REFERENCES cves (id) ON DELETE CASCADE,
    model TEXT NOT NULL,
    explanation TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT cve_explanations_model_chk CHECK (model = 'gemini-2.5-flash-lite'),
    CONSTRAINT cve_explanations_text_chk CHECK (length(btrim(explanation)) > 0)
);

COMMENT ON TABLE cve_explanations IS
    'Plain-language guidance for one CVE. Produced by gemini-2.5-flash-lite with thinking off. Not an assessment, and not a description of how to exploit the flaw.';
