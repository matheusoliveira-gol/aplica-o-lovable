-- Allow all authenticated users to view group permissions (read-only)
DROP POLICY IF EXISTS "Admin can view all permissions" ON public.group_permissions;

CREATE POLICY "Authenticated users can view permissions"
ON public.group_permissions FOR SELECT
TO authenticated
USING (true);

-- Keep admin-only policies for modifications
-- (insert, update, delete policies remain unchanged)