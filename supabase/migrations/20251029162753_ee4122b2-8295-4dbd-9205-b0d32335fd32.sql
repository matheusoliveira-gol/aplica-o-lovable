-- Add nome_mae and nome_pai columns to pessoas table
ALTER TABLE public.pessoas 
ADD COLUMN IF NOT EXISTS nome_mae TEXT,
ADD COLUMN IF NOT EXISTS nome_pai TEXT;