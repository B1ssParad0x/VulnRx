-- One saved Gemini reply per question and per hospital. A repeat does not call the API.

CREATE TABLE nl_answers (
    question_key TEXT PRIMARY KEY,
    question TEXT NOT NULL,
    model TEXT NOT NULL,
    answer TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT nl_answers_model_chk CHECK (model = 'gemini-3.5-flash-lite'),
    CONSTRAINT nl_answers_question_chk CHECK (length(btrim(question)) > 0),
    CONSTRAINT nl_answers_text_chk CHECK (length(btrim(answer)) > 0)
);

COMMENT ON TABLE nl_answers IS
    'A short answer to one question, using only facts already stored. Not an assessment.';

CREATE TABLE hospital_guidance (
    hospital_id UUID PRIMARY KEY REFERENCES hospitals (id) ON DELETE CASCADE,
    model TEXT NOT NULL,
    guidance TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT hospital_guidance_model_chk CHECK (model = 'gemini-3.5-flash-lite'),
    CONSTRAINT hospital_guidance_text_chk CHECK (length(btrim(guidance)) > 0)
);

COMMENT ON TABLE hospital_guidance IS
    'Next steps for one hospital from its linked records. Not an assessment, and not exploit instructions.';
