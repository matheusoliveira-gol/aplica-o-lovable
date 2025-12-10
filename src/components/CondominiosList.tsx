import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Trash2 } from "lucide-react";
import { toast } from "sonner";
import { db } from "@/lib/localDB";

interface Condominio {
  id: string;
  nome: string;
  created_at: string;
}

const CondominiosList = () => {
  const [condominios, setCondominios] = useState<Condominio[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchCondominios = async () => {
    try {
      const data = await db.condominios.orderBy('created_at').reverse().toArray();
      setCondominios(data || []);
    } catch (error: any) {
      console.error("Erro ao carregar condomínios:", error);
      toast.error("Erro ao carregar condomínios");
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm("Tem certeza que deseja excluir este condomínio?")) return;

    try {
      // Verificar se existem pessoas vinculadas
      const pessoasVinculadas = await db.pessoas_condominios
        .where('condominio_id')
        .equals(id)
        .count();
      
      if (pessoasVinculadas > 0) {
        toast.error("Não é possível excluir este condomínio pois existem pessoas vinculadas a ele");
        return;
      }

      await db.condominios.delete(id);
      toast.success("Condomínio excluído com sucesso!");
      fetchCondominios();
    } catch (error: any) {
      console.error("Erro ao excluir condomínio:", error);
      toast.error("Erro ao excluir condomínio");
    }
  };

  useEffect(() => {
    fetchCondominios();
  }, []);

  if (loading) {
    return <div>Carregando...</div>;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Condomínios Cadastrados</CardTitle>
      </CardHeader>
      <CardContent>
        {condominios.length === 0 ? (
          <p className="text-muted-foreground">Nenhum condomínio cadastrado.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Nome</TableHead>
                <TableHead>Data de Cadastro</TableHead>
                <TableHead className="text-right">Ações</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {condominios.map((condominio) => (
                <TableRow key={condominio.id}>
                  <TableCell>{condominio.nome}</TableCell>
                  <TableCell>
                    {new Date(condominio.created_at).toLocaleDateString("pt-BR")}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="destructive"
                      size="sm"
                      onClick={() => handleDelete(condominio.id)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
};

export default CondominiosList;
