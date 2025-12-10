-- Criar tabela de profiles (perfis de usuários)
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  full_name TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable RLS
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Políticas RLS para profiles
CREATE POLICY "Users can view own profile"
  ON public.profiles FOR SELECT
  USING (auth.uid() = id);

CREATE POLICY "Users can update own profile"
  ON public.profiles FOR UPDATE
  USING (auth.uid() = id);

-- Trigger para criar profile automaticamente
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER SET search_path = public
AS $$
BEGIN
  INSERT INTO public.profiles (id, email, full_name)
  VALUES (NEW.id, NEW.email, NEW.raw_user_meta_data->>'full_name');
  RETURN NEW;
END;
$$;

CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Criar tabela de artigos
CREATE TABLE IF NOT EXISTS public.artigos (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  numero TEXT NOT NULL UNIQUE,
  nome TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.artigos ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can view artigos"
  ON public.artigos FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert artigos"
  ON public.artigos FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "Authenticated users can update artigos"
  ON public.artigos FOR UPDATE
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can delete artigos"
  ON public.artigos FOR DELETE
  TO authenticated
  USING (true);

-- Criar tabela de pessoas
CREATE TABLE IF NOT EXISTS public.pessoas (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  foto_url TEXT,
  nome TEXT NOT NULL,
  rg TEXT NOT NULL,
  cpf TEXT,
  data_nascimento DATE,
  residencial TEXT NOT NULL,
  created_by UUID REFERENCES auth.users(id),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE public.pessoas ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can view pessoas"
  ON public.pessoas FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert pessoas"
  ON public.pessoas FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "Authenticated users can update pessoas"
  ON public.pessoas FOR UPDATE
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can delete pessoas"
  ON public.pessoas FOR DELETE
  TO authenticated
  USING (true);

-- Tabela de relacionamento pessoas-artigos (muitos para muitos)
CREATE TABLE IF NOT EXISTS public.pessoas_artigos (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  pessoa_id UUID NOT NULL REFERENCES public.pessoas(id) ON DELETE CASCADE,
  artigo_id UUID NOT NULL REFERENCES public.artigos(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(pessoa_id, artigo_id)
);

ALTER TABLE public.pessoas_artigos ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users can view pessoas_artigos"
  ON public.pessoas_artigos FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert pessoas_artigos"
  ON public.pessoas_artigos FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "Authenticated users can delete pessoas_artigos"
  ON public.pessoas_artigos FOR DELETE
  TO authenticated
  USING (true);

-- Trigger para atualizar updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_profiles_updated_at BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_artigos_updated_at BEFORE UPDATE ON public.artigos
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_pessoas_updated_at BEFORE UPDATE ON public.pessoas
  FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Criar bucket para fotos
INSERT INTO storage.buckets (id, name, public) 
VALUES ('pessoas-fotos', 'pessoas-fotos', true)
ON CONFLICT (id) DO NOTHING;

-- Políticas de storage
CREATE POLICY "Anyone can view fotos"
  ON storage.objects FOR SELECT
  USING (bucket_id = 'pessoas-fotos');

CREATE POLICY "Authenticated users can upload fotos"
  ON storage.objects FOR INSERT
  TO authenticated
  WITH CHECK (bucket_id = 'pessoas-fotos');

CREATE POLICY "Authenticated users can update fotos"
  ON storage.objects FOR UPDATE
  TO authenticated
  USING (bucket_id = 'pessoas-fotos');

CREATE POLICY "Authenticated users can delete fotos"
  ON storage.objects FOR DELETE
  TO authenticated
  USING (bucket_id = 'pessoas-fotos');