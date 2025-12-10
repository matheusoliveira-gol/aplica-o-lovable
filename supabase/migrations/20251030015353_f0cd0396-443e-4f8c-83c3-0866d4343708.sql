-- Create condominios table
CREATE TABLE public.condominios (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  nome TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.condominios ENABLE ROW LEVEL SECURITY;

-- Create enum for user roles/groups
CREATE TYPE public.user_group AS ENUM ('admin', 'gestor', 'operador', 'visualizador');

-- Create user_roles table
CREATE TABLE public.user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE NOT NULL,
  group_role user_group NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  UNIQUE(user_id)
);

-- Enable RLS
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

-- Create permissions table for CRUD operations
CREATE TABLE public.group_permissions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  group_role user_group NOT NULL,
  resource TEXT NOT NULL, -- 'pessoas', 'artigos', 'condominios', 'usuarios'
  can_create BOOLEAN DEFAULT false,
  can_read BOOLEAN DEFAULT false,
  can_update BOOLEAN DEFAULT false,
  can_delete BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  UNIQUE(group_role, resource)
);

-- Enable RLS
ALTER TABLE public.group_permissions ENABLE ROW LEVEL SECURITY;

-- Security definer function to check user role
CREATE OR REPLACE FUNCTION public.get_user_role(_user_id UUID)
RETURNS user_group
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT group_role FROM public.user_roles WHERE user_id = _user_id LIMIT 1;
$$;

-- Security definer function to check if user has permission
CREATE OR REPLACE FUNCTION public.has_permission(_user_id UUID, _resource TEXT, _operation TEXT)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT CASE _operation
    WHEN 'create' THEN COALESCE((SELECT can_create FROM public.group_permissions gp 
                                  JOIN public.user_roles ur ON ur.group_role = gp.group_role 
                                  WHERE ur.user_id = _user_id AND gp.resource = _resource), false)
    WHEN 'read' THEN COALESCE((SELECT can_read FROM public.group_permissions gp 
                                JOIN public.user_roles ur ON ur.group_role = gp.group_role 
                                WHERE ur.user_id = _user_id AND gp.resource = _resource), false)
    WHEN 'update' THEN COALESCE((SELECT can_update FROM public.group_permissions gp 
                                  JOIN public.user_roles ur ON ur.group_role = gp.group_role 
                                  WHERE ur.user_id = _user_id AND gp.resource = _resource), false)
    WHEN 'delete' THEN COALESCE((SELECT can_delete FROM public.group_permissions gp 
                                  JOIN public.user_roles ur ON ur.group_role = gp.group_role 
                                  WHERE ur.user_id = _user_id AND gp.resource = _resource), false)
    ELSE false
  END;
$$;

-- RLS Policies for condominios
CREATE POLICY "Users can read condominios if they have permission"
ON public.condominios FOR SELECT
TO authenticated
USING (public.has_permission(auth.uid(), 'condominios', 'read'));

CREATE POLICY "Users can insert condominios if they have permission"
ON public.condominios FOR INSERT
TO authenticated
WITH CHECK (public.has_permission(auth.uid(), 'condominios', 'create'));

CREATE POLICY "Users can update condominios if they have permission"
ON public.condominios FOR UPDATE
TO authenticated
USING (public.has_permission(auth.uid(), 'condominios', 'update'));

CREATE POLICY "Users can delete condominios if they have permission"
ON public.condominios FOR DELETE
TO authenticated
USING (public.has_permission(auth.uid(), 'condominios', 'delete'));

-- RLS Policies for user_roles (only admin can manage)
CREATE POLICY "Admin can view all user roles"
ON public.user_roles FOR SELECT
TO authenticated
USING (public.get_user_role(auth.uid()) = 'admin');

CREATE POLICY "Admin can insert user roles"
ON public.user_roles FOR INSERT
TO authenticated
WITH CHECK (public.get_user_role(auth.uid()) = 'admin');

CREATE POLICY "Admin can update user roles"
ON public.user_roles FOR UPDATE
TO authenticated
USING (public.get_user_role(auth.uid()) = 'admin');

CREATE POLICY "Admin can delete user roles"
ON public.user_roles FOR DELETE
TO authenticated
USING (public.get_user_role(auth.uid()) = 'admin');

-- RLS Policies for group_permissions (only admin can manage)
CREATE POLICY "Admin can view all permissions"
ON public.group_permissions FOR SELECT
TO authenticated
USING (public.get_user_role(auth.uid()) = 'admin');

CREATE POLICY "Admin can insert permissions"
ON public.group_permissions FOR INSERT
TO authenticated
WITH CHECK (public.get_user_role(auth.uid()) = 'admin');

CREATE POLICY "Admin can update permissions"
ON public.group_permissions FOR UPDATE
TO authenticated
USING (public.get_user_role(auth.uid()) = 'admin');

CREATE POLICY "Admin can delete permissions"
ON public.group_permissions FOR DELETE
TO authenticated
USING (public.get_user_role(auth.uid()) = 'admin');

-- Update existing RLS policies for pessoas
DROP POLICY IF EXISTS "Authenticated users can view pessoas" ON public.pessoas;
DROP POLICY IF EXISTS "Authenticated users can insert pessoas" ON public.pessoas;
DROP POLICY IF EXISTS "Authenticated users can update pessoas" ON public.pessoas;
DROP POLICY IF EXISTS "Authenticated users can delete pessoas" ON public.pessoas;

CREATE POLICY "Users can read pessoas if they have permission"
ON public.pessoas FOR SELECT
TO authenticated
USING (public.has_permission(auth.uid(), 'pessoas', 'read'));

CREATE POLICY "Users can insert pessoas if they have permission"
ON public.pessoas FOR INSERT
TO authenticated
WITH CHECK (public.has_permission(auth.uid(), 'pessoas', 'create'));

CREATE POLICY "Users can update pessoas if they have permission"
ON public.pessoas FOR UPDATE
TO authenticated
USING (public.has_permission(auth.uid(), 'pessoas', 'update'));

CREATE POLICY "Users can delete pessoas if they have permission"
ON public.pessoas FOR DELETE
TO authenticated
USING (public.has_permission(auth.uid(), 'pessoas', 'delete'));

-- Update existing RLS policies for artigos
DROP POLICY IF EXISTS "Authenticated users can view artigos" ON public.artigos;
DROP POLICY IF EXISTS "Authenticated users can insert artigos" ON public.artigos;
DROP POLICY IF EXISTS "Authenticated users can update artigos" ON public.artigos;
DROP POLICY IF EXISTS "Authenticated users can delete artigos" ON public.artigos;

CREATE POLICY "Users can read artigos if they have permission"
ON public.artigos FOR SELECT
TO authenticated
USING (public.has_permission(auth.uid(), 'artigos', 'read'));

CREATE POLICY "Users can insert artigos if they have permission"
ON public.artigos FOR INSERT
TO authenticated
WITH CHECK (public.has_permission(auth.uid(), 'artigos', 'create'));

CREATE POLICY "Users can update artigos if they have permission"
ON public.artigos FOR UPDATE
TO authenticated
USING (public.has_permission(auth.uid(), 'artigos', 'update'));

CREATE POLICY "Users can delete artigos if they have permission"
ON public.artigos FOR DELETE
TO authenticated
USING (public.has_permission(auth.uid(), 'artigos', 'delete'));

-- Trigger for updated_at on condominios
CREATE TRIGGER update_condominios_updated_at
BEFORE UPDATE ON public.condominios
FOR EACH ROW
EXECUTE FUNCTION public.update_updated_at_column();

-- Insert default permissions for admin group
INSERT INTO public.group_permissions (group_role, resource, can_create, can_read, can_update, can_delete) VALUES
('admin', 'pessoas', true, true, true, true),
('admin', 'artigos', true, true, true, true),
('admin', 'condominios', true, true, true, true),
('admin', 'usuarios', true, true, true, true),
('gestor', 'pessoas', true, true, true, true),
('gestor', 'artigos', true, true, true, true),
('gestor', 'condominios', true, true, true, false),
('gestor', 'usuarios', false, true, false, false),
('operador', 'pessoas', true, true, true, false),
('operador', 'artigos', true, true, true, false),
('operador', 'condominios', false, true, false, false),
('operador', 'usuarios', false, false, false, false),
('visualizador', 'pessoas', false, true, false, false),
('visualizador', 'artigos', false, true, false, false),
('visualizador', 'condominios', false, true, false, false),
('visualizador', 'usuarios', false, false, false, false);