-- New Gemini projects are pointed at Flash-Lite 3.5. Keep one allowed model so a reply's source stays obvious.

ALTER TABLE cve_explanations DROP CONSTRAINT cve_explanations_model_chk;
ALTER TABLE cve_explanations
    ADD CONSTRAINT cve_explanations_model_chk CHECK (model = 'gemini-3.5-flash-lite');

COMMENT ON TABLE cve_explanations IS
    'Plain-language guidance for one CVE. Produced by gemini-3.5-flash-lite with thinking off. Not an assessment, and not a description of how to exploit the flaw.';
