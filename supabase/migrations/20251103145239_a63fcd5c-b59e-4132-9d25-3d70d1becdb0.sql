-- Tornar o campo residencial opcional na tabela pessoas
ALTER TABLE public.pessoas 
ALTER COLUMN residencial DROP NOT NULL;