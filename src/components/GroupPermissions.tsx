import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Checkbox } from "@/components/ui/checkbox";
import { toast } from "sonner";
import { groupPermissionsAPI, GroupPermission } from "@/lib/api";

const GroupPermissions = () => {
  const [permissions, setPermissions] = useState<GroupPermission[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchPermissions = async () => {
    try {
      const data = await groupPermissionsAPI.getAll();
      // Sort by group_role and resource
      const sorted = (data || []).sort((a, b) => {
        if (a.group_role !== b.group_role) {
          return a.group_role.localeCompare(b.group_role);
        }
        return a.resource.localeCompare(b.resource);
      });
      setPermissions(sorted);
    } catch (error: any) {
      console.error("Erro ao carregar permissões:", error);
      toast.error("Erro ao carregar permissões");
    } finally {
      setLoading(false);
    }
  };

  const handlePermissionChange = async (
    id: string,
    field: "can_create" | "can_read" | "can_update" | "can_delete",
    value: boolean
  ) => {
    try {
      await groupPermissionsAPI.update(id, { 
        [field]: value,
        updated_at: new Date().toISOString()
      });

      setPermissions((prev) =>
        prev.map((perm) => (perm.id === id ? { ...perm, [field]: value } : perm))
      );

      toast.success("Permissão atualizada com sucesso!");
    } catch (error: any) {
      console.error("Erro ao atualizar permissão:", error);
      toast.error("Erro ao atualizar permissão");
    }
  };

  useEffect(() => {
    fetchPermissions();
  }, []);

  if (loading) {
    return <div>Carregando...</div>;
  }

  const groupedPermissions = permissions.reduce((acc, perm) => {
    if (!acc[perm.group_role]) {
      acc[perm.group_role] = [];
    }
    acc[perm.group_role].push(perm);
    return acc;
  }, {} as Record<string, GroupPermission[]>);

  const groupNames: Record<string, string> = {
    admin: "Admin",
    gestor: "Gestor",
    operador: "Operador",
    visualizador: "Visualizador",
  };

  const resourceNames: Record<string, string> = {
    pessoas: "Pessoas",
    artigos: "Códigos",
    condominios: "Condomínios",
    usuarios: "Usuários",
  };

  return (
    <div className="space-y-4">
      {Object.entries(groupedPermissions).map(([groupRole, perms]) => (
        <div key={groupRole} className="border rounded-lg">
          <div className="p-4 border-b bg-muted/50">
            <h3 className="font-semibold">{groupNames[groupRole] || groupRole}</h3>
          </div>
          <div className="p-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Recurso</TableHead>
                  <TableHead className="text-center">Criar</TableHead>
                  <TableHead className="text-center">Ler</TableHead>
                  <TableHead className="text-center">Atualizar</TableHead>
                  <TableHead className="text-center">Deletar</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {perms.map((perm) => (
                  <TableRow key={perm.id}>
                    <TableCell>{resourceNames[perm.resource] || perm.resource}</TableCell>
                    <TableCell className="text-center">
                      <Checkbox
                        checked={perm.can_create}
                        onCheckedChange={(checked) =>
                          handlePermissionChange(perm.id, "can_create", checked as boolean)
                        }
                      />
                    </TableCell>
                    <TableCell className="text-center">
                      <Checkbox
                        checked={perm.can_read}
                        onCheckedChange={(checked) =>
                          handlePermissionChange(perm.id, "can_read", checked as boolean)
                        }
                      />
                    </TableCell>
                    <TableCell className="text-center">
                      <Checkbox
                        checked={perm.can_update}
                        onCheckedChange={(checked) =>
                          handlePermissionChange(perm.id, "can_update", checked as boolean)
                        }
                      />
                    </TableCell>
                    <TableCell className="text-center">
                      <Checkbox
                        checked={perm.can_delete}
                        onCheckedChange={(checked) =>
                          handlePermissionChange(perm.id, "can_delete", checked as boolean)
                        }
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </div>
      ))}
    </div>
  );
};

export default GroupPermissions;
