import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";
import { toast } from "sonner";
import { Link, CalendarIcon, Trash2, Plus } from "lucide-react";
import { cn } from "@/lib/utils";
import { condominiosAPI, pessoasCondominiosAPI, Condominio, generateUUID } from "@/lib/api";

interface VincularCondominiosDialogProps {
  pessoaId: string;
  pessoaNome: string;
}

interface Vinculo {
  id: string;
  condominio_id: string;
  data_vinculo: string;
  condominio_nome: string;
}

export const VincularCondominiosDialog = ({ pessoaId, pessoaNome }: VincularCondominiosDialogProps) => {
  const [open, setOpen] = useState(false);
  const [condominios, setCondominios] = useState<Condominio[]>([]);
  const [vinculos, setVinculos] = useState<Vinculo[]>([]);
  const [selectedCondominio, setSelectedCondominio] = useState<string>("");
  const [selectedDate, setSelectedDate] = useState<Date>();
  const [loading, setLoading] = useState(false);

  const fetchCondominios = async () => {
    try {
      const data = await condominiosAPI.getAll();
      setCondominios(data || []);
    } catch (error) {
      toast.error("Erro ao carregar condomínios");
    }
  };

  const fetchVinculos = async () => {
    try {
      const [allVinculos, allCondominios] = await Promise.all([
        pessoasCondominiosAPI.getAll(),
        condominiosAPI.getAll(),
      ]);

      const condominiosMap = new Map<string, string>();
      allCondominios.forEach(c => condominiosMap.set(c.id, c.nome));

      const pessoaVinculos = allVinculos
        .filter(v => v.pessoa_id === pessoaId)
        .map(v => ({
          id: v.id,
          condominio_id: v.condominio_id,
          data_vinculo: v.data_vinculo,
          condominio_nome: condominiosMap.get(v.condominio_id) || 'Desconhecido',
        }))
        .sort((a, b) => new Date(b.data_vinculo).getTime() - new Date(a.data_vinculo).getTime());

      setVinculos(pessoaVinculos);
    } catch (error) {
      toast.error("Erro ao carregar vínculos");
    }
  };

  useEffect(() => {
    if (open) {
      fetchCondominios();
      fetchVinculos();
    }
  }, [open, pessoaId]);

  const handleAddVinculo = async () => {
    if (!selectedCondominio || !selectedDate) {
      toast.error("Selecione um condomínio e uma data");
      return;
    }

    setLoading(true);
    try {
      const now = new Date().toISOString();
      await pessoasCondominiosAPI.create({
        id: generateUUID(),
        pessoa_id: pessoaId,
        condominio_id: selectedCondominio,
        data_vinculo: format(selectedDate, "yyyy-MM-dd"),
        created_at: now,
        updated_at: now,
      });

      toast.success("Vínculo adicionado com sucesso!");
      setSelectedCondominio("");
      setSelectedDate(undefined);
      fetchVinculos();
    } catch (error: any) {
      toast.error("Erro ao adicionar vínculo: " + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteVinculo = async (vinculoId: string) => {
    try {
      await pessoasCondominiosAPI.delete(vinculoId);
      toast.success("Vínculo removido com sucesso!");
      fetchVinculos();
    } catch (error: any) {
      toast.error("Erro ao remover vínculo: " + error.message);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="sm">
          <Link className="h-4 w-4" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Vincular Condomínios</DialogTitle>
          <DialogDescription>
            Gerencie os vínculos de <strong>{pessoaNome}</strong> com condomínios
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6">
          {/* Form para adicionar novo vínculo */}
          <div className="border rounded-lg p-4 space-y-4">
            <h3 className="font-semibold flex items-center gap-2">
              <Plus className="h-4 w-4" />
              Adicionar Novo Vínculo
            </h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <label className="text-sm font-medium">Condomínio</label>
                <Select value={selectedCondominio} onValueChange={setSelectedCondominio}>
                  <SelectTrigger>
                    <SelectValue placeholder="Selecione um condomínio" />
                  </SelectTrigger>
                  <SelectContent>
                    {condominios.map((cond) => (
                      <SelectItem key={cond.id} value={cond.id}>
                        {cond.nome}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Data do Vínculo</label>
                <Popover>
                  <PopoverTrigger asChild>
                    <Button
                      variant="outline"
                      className={cn(
                        "w-full justify-start text-left font-normal",
                        !selectedDate && "text-muted-foreground"
                      )}
                    >
                      <CalendarIcon className="mr-2 h-4 w-4" />
                      {selectedDate ? format(selectedDate, "dd/MM/yyyy", { locale: ptBR }) : "Selecione uma data"}
                    </Button>
                  </PopoverTrigger>
                  <PopoverContent className="w-auto p-0" align="start">
                    <Calendar
                      mode="single"
                      selected={selectedDate}
                      onSelect={setSelectedDate}
                      initialFocus
                      className="pointer-events-auto"
                    />
                  </PopoverContent>
                </Popover>
              </div>
            </div>

            <Button onClick={handleAddVinculo} disabled={loading} className="w-full">
              <Plus className="h-4 w-4 mr-2" />
              Adicionar Vínculo
            </Button>
          </div>

          {/* Lista de vínculos existentes */}
          <div className="space-y-2">
            <h3 className="font-semibold">Vínculos Existentes</h3>
            {vinculos.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground border rounded-lg">
                Nenhum vínculo cadastrado ainda.
              </div>
            ) : (
              <div className="border rounded-lg">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Condomínio</TableHead>
                      <TableHead>Data do Vínculo</TableHead>
                      <TableHead className="text-right">Ações</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {vinculos.map((vinculo) => (
                      <TableRow key={vinculo.id}>
                        <TableCell className="font-medium">
                          {vinculo.condominio_nome}
                        </TableCell>
                        <TableCell>
                          {format(new Date(vinculo.data_vinculo), "dd/MM/yyyy", { locale: ptBR })}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeleteVinculo(vinculo.id)}
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};
