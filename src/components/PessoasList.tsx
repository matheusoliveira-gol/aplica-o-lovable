import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";
import { toast } from "sonner";
import { Trash2, Pencil, Search } from "lucide-react";
import { VincularCondominiosDialog } from "./VincularCondominiosDialog";
import { PersonDetailsDialog } from "./PersonDetailsDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { pessoasAPI, artigosAPI, condominiosAPI, pessoasArtigosAPI, pessoasCondominiosAPI, Pessoa, Artigo, Condominio } from "@/lib/api";

interface PessoaWithRelations extends Pessoa {
  artigos: Array<{ id: string; numero: string; nome: string }>;
  condominios: Array<{ id: string; nome: string; data_vinculo: string }>;
}

const PessoasList = () => {
  const navigate = useNavigate();
  const [pessoas, setPessoas] = useState<PessoaWithRelations[]>([]);
  const [loading, setLoading] = useState(true);
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedPessoa, setSelectedPessoa] = useState<PessoaWithRelations | null>(null);

  const fetchPessoas = async () => {
    try {
      setLoading(true);
      
      // Buscar todos os dados em paralelo
      const [pessoasData, artigosData, condominiosData, pessoasArtigosData, pessoasCondominiosData] = await Promise.all([
        pessoasAPI.getAll(),
        artigosAPI.getAll(),
        condominiosAPI.getAll(),
        pessoasArtigosAPI.getAll(),
        pessoasCondominiosAPI.getAll(),
      ]);

      // Mapear artigos e condomínios por ID
      const artigosMap = new Map<string, Artigo>();
      artigosData.forEach(a => artigosMap.set(a.id, a));
      
      const condominiosMap = new Map<string, Condominio>();
      condominiosData.forEach(c => condominiosMap.set(c.id, c));

      // Montar pessoas com relações
      const pessoasComDados = pessoasData.map((pessoa) => {
        // Buscar artigos da pessoa
        const artigoIds = pessoasArtigosData
          .filter(pa => pa.pessoa_id === pessoa.id)
          .map(pa => pa.artigo_id);
        
        const artigos = artigoIds
          .map(id => artigosMap.get(id))
          .filter(Boolean)
          .map(a => ({ id: a!.id, numero: a!.numero, nome: a!.nome }));

        // Buscar condomínios da pessoa
        const condominioVinculos = pessoasCondominiosData
          .filter(pc => pc.pessoa_id === pessoa.id)
          .sort((a, b) => new Date(b.data_vinculo).getTime() - new Date(a.data_vinculo).getTime());
        
        const condominios = condominioVinculos
          .map(cv => {
            const cond = condominiosMap.get(cv.condominio_id);
            return cond ? { id: cond.id, nome: cond.nome, data_vinculo: cv.data_vinculo } : null;
          })
          .filter(Boolean) as Array<{ id: string; nome: string; data_vinculo: string }>;

        return {
          ...pessoa,
          artigos,
          condominios,
        };
      });

      // Ordenar por data de criação (mais recente primeiro)
      pessoasComDados.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

      setPessoas(pessoasComDados);
    } catch (error: any) {
      toast.error("Erro ao carregar pessoas: " + error.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPessoas();
  }, []);

  const handleDelete = async () => {
    if (!deleteId) return;
    
    try {
      await pessoasAPI.delete(deleteId);
      toast.success("Pessoa excluída com sucesso!");
      fetchPessoas();
    } catch (error: any) {
      toast.error("Erro ao excluir: " + error.message);
    } finally {
      setDeleteId(null);
    }
  };

  if (loading) {
    return (
      <div className="text-center py-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto"></div>
      </div>
    );
  }

  const filteredPessoas = pessoas.filter((pessoa) => {
    const searchLower = searchTerm.toLowerCase();
    return (
      pessoa.nome.toLowerCase().includes(searchLower) ||
      pessoa.rg.toLowerCase().includes(searchLower) ||
      pessoa.cpf?.toLowerCase().includes(searchLower) ||
      pessoa.condominios.some(c => c.nome.toLowerCase().includes(searchLower))
    );
  });

  if (pessoas.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        Nenhuma pessoa cadastrada ainda.
      </div>
    );
  }

  return (
    <>
      <div className="mb-4 flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Buscar por nome, RG, CPF ou residencial..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-10"
          />
        </div>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Foto</TableHead>
              <TableHead>Nome</TableHead>
              <TableHead>RG</TableHead>
              <TableHead>Nome da Mãe</TableHead>
              <TableHead>Residencial</TableHead>
              <TableHead>Código</TableHead>
              <TableHead>Cadastrado em</TableHead>
              <TableHead>Atualizado em</TableHead>
              <TableHead className="text-right">Ações</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredPessoas.map((pessoa) => (
              <TableRow key={pessoa.id}>
                <TableCell>
                  <Avatar>
                    <AvatarImage src={pessoa.foto_url || undefined} />
                    <AvatarFallback>{pessoa.nome.substring(0, 2).toUpperCase()}</AvatarFallback>
                  </Avatar>
                </TableCell>
                <TableCell>
                  <button
                    onClick={() => setSelectedPessoa(pessoa)}
                    className="font-medium hover:underline cursor-pointer text-left"
                  >
                    {pessoa.nome}
                  </button>
                </TableCell>
                <TableCell>{pessoa.rg}</TableCell>
                <TableCell>{pessoa.nome_mae || "-"}</TableCell>
                <TableCell>
                  {pessoa.condominios.length > 0 ? (
                    <span>
                      {pessoa.condominios[0].nome}
                      {pessoa.condominios.length > 1 && (
                        <span className="text-muted-foreground ml-1">
                          (+{pessoa.condominios.length - 1})
                        </span>
                      )}
                    </span>
                  ) : (
                    <span className="text-muted-foreground">-</span>
                  )}
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {pessoa.artigos.slice(0, 3).map((artigo) => (
                      <Badge key={artigo.id} variant="secondary">
                        {artigo.numero}
                      </Badge>
                    ))}
                    {pessoa.artigos.length > 3 && (
                      <Badge variant="secondary" className="text-muted-foreground">
                        (+{pessoa.artigos.length - 3})
                      </Badge>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  {format(new Date(pessoa.created_at), "dd/MM/yyyy HH:mm", { locale: ptBR })}
                </TableCell>
                <TableCell>
                  {format(new Date(pessoa.updated_at), "dd/MM/yyyy HH:mm", { locale: ptBR })}
                </TableCell>
                <TableCell className="text-right">
                  <div className="flex justify-end gap-2">
                    <VincularCondominiosDialog 
                      pessoaId={pessoa.id} 
                      pessoaNome={pessoa.nome}
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => navigate(`/cadastrar-pessoa?id=${pessoa.id}`)}
                    >
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setDeleteId(pessoa.id)}
                    >
                      <Trash2 className="h-4 w-4 text-destructive" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <AlertDialog open={!!deleteId} onOpenChange={() => setDeleteId(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Confirmar exclusão</AlertDialogTitle>
            <AlertDialogDescription>
              Tem certeza que deseja excluir esta pessoa? Esta ação não pode ser desfeita.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancelar</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete}>Excluir</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {selectedPessoa && (
        <PersonDetailsDialog
          open={!!selectedPessoa}
          onOpenChange={(open) => !open && setSelectedPessoa(null)}
          pessoa={selectedPessoa}
        />
      )}
    </>
  );
};

export default PessoasList;
