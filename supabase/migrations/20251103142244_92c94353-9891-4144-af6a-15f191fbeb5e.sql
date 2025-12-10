-- Create pessoas_condominios table to link pessoas to condominios with dates
CREATE TABLE public.pessoas_condominios (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  pessoa_id UUID NOT NULL REFERENCES public.pessoas(id) ON DELETE CASCADE,
  condominio_id UUID NOT NULL REFERENCES public.condominios(id) ON DELETE CASCADE,
  data_vinculo DATE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable Row Level Security
ALTER TABLE public.pessoas_condominios ENABLE ROW LEVEL SECURITY;

-- Create policies for pessoas_condominios
CREATE POLICY "Users can read pessoas_condominios if they have permission"
ON public.pessoas_condominios FOR SELECT
USING (has_permission(auth.uid(), 'pessoas'::text, 'read'::text));

CREATE POLICY "Users can insert pessoas_condominios if they have permission"
ON public.pessoas_condominios FOR INSERT
WITH CHECK (has_permission(auth.uid(), 'pessoas'::text, 'create'::text));

CREATE POLICY "Users can update pessoas_condominios if they have permission"
ON public.pessoas_condominios FOR UPDATE
USING (has_permission(auth.uid(), 'pessoas'::text, 'update'::text));

CREATE POLICY "Users can delete pessoas_condominios if they have permission"
ON public.pessoas_condominios FOR DELETE
USING (has_permission(auth.uid(), 'pessoas'::text, 'delete'::text));

-- Create trigger for automatic timestamp updates
CREATE TRIGGER update_pessoas_condominios_updated_at
BEFORE UPDATE ON public.pessoas_condominios
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

-- Create index for better query performance
CREATE INDEX idx_pessoas_condominios_pessoa_id ON public.pessoas_condominios(pessoa_id);
CREATE INDEX idx_pessoas_condominios_condominio_id ON public.pessoas_condominios(condominio_id);