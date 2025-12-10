import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";

interface PersonDetailsDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pessoa: {
    nome: string;
    rg: string;
    cpf?: string | null;
    data_nascimento?: string | null;
    residencial?: string | null;
    foto_url?: string | null;
    nome_mae?: string | null;
    nome_pai?: string | null;
    observacao?: string | null;
    created_at: string;
    updated_at: string;
    artigos: Array<{ id: string; numero: string; nome: string }>;
    condominios: Array<{ id: string; nome: string; data_vinculo: string }>;
  };
}

export const PersonDetailsDialog = ({ open, onOpenChange, pessoa }: PersonDetailsDialogProps) => {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3">
            <Avatar className="h-12 w-12">
              <AvatarImage src={pessoa.foto_url || undefined} />
              <AvatarFallback>{pessoa.nome.substring(0, 2).toUpperCase()}</AvatarFallback>
            </Avatar>
            <span>{pessoa.nome}</span>
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4">
          <div>
            <h3 className="font-semibold mb-2">Informações Pessoais</h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-muted-foreground">RG:</span>
                <p className="font-medium">{pessoa.rg}</p>
              </div>
              {pessoa.cpf && (
                <div>
                  <span className="text-muted-foreground">CPF:</span>
                  <p className="font-medium">{pessoa.cpf}</p>
                </div>
              )}
              {pessoa.data_nascimento && (
                <div>
                  <span className="text-muted-foreground">Data de Nascimento:</span>
                  <p className="font-medium">
                    {format(new Date(pessoa.data_nascimento), "dd/MM/yyyy", { locale: ptBR })}
                  </p>
                </div>
              )}
              {pessoa.nome_mae && (
                <div>
                  <span className="text-muted-foreground">Nome da Mãe:</span>
                  <p className="font-medium">{pessoa.nome_mae}</p>
                </div>
              )}
              {pessoa.nome_pai && (
                <div>
                  <span className="text-muted-foreground">Nome do Pai:</span>
                  <p className="font-medium">{pessoa.nome_pai}</p>
                </div>
              )}
            </div>
          </div>

          <Separator />

          <div>
            <h3 className="font-semibold mb-2">Condomínios</h3>
            {pessoa.condominios.length > 0 ? (
              <div className="space-y-2">
                {pessoa.condominios.map((cond) => (
                  <div key={cond.id} className="flex justify-between items-center text-sm">
                    <span className="font-medium">{cond.nome}</span>
                    <span className="text-muted-foreground">
                      Vinculado em: {format(new Date(cond.data_vinculo), "dd/MM/yyyy", { locale: ptBR })}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Nenhum condomínio vinculado</p>
            )}
          </div>

          <Separator />

          <div>
            <h3 className="font-semibold mb-2">Códigos (Artigos)</h3>
            {pessoa.artigos.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {pessoa.artigos.map((artigo) => (
                  <Badge key={artigo.id} variant="secondary">
                    {artigo.numero} - {artigo.nome}
                  </Badge>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Nenhum código vinculado</p>
            )}
          </div>

          {pessoa.observacao && (
            <>
              <Separator />
              <div>
                <h3 className="font-semibold mb-2">Observações</h3>
                <p className="text-sm whitespace-pre-wrap">{pessoa.observacao}</p>
              </div>
            </>
          )}

          <Separator />

          <div className="grid grid-cols-2 gap-3 text-xs text-muted-foreground">
            <div>
              <span>Cadastrado em:</span>
              <p>{format(new Date(pessoa.created_at), "dd/MM/yyyy HH:mm", { locale: ptBR })}</p>
            </div>
            <div>
              <span>Atualizado em:</span>
              <p>{format(new Date(pessoa.updated_at), "dd/MM/yyyy HH:mm", { locale: ptBR })}</p>
            </div>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
};
