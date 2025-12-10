import { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { ArrowLeft, Upload, X } from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import { z } from "zod";
import InputMask from "react-input-mask";
import { pessoasAPI, artigosAPI, pessoasArtigosAPI, Artigo, generateUUID } from "@/lib/api";

const pessoaSchema = z.object({
  nome: z.string().trim().min(1, "Nome é obrigatório").max(200),
  rg: z.string().trim().min(1, "RG é obrigatório").max(20),
  cpf: z.string().trim().optional(),
  data_nascimento: z.string().optional(),
  nome_mae: z.string().trim().optional(),
  nome_pai: z.string().trim().optional(),
});

const CadastrarPessoa = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const pessoaId = searchParams.get("id");
  const [loading, setLoading] = useState(false);
  const [artigos, setArtigos] = useState<Artigo[]>([]);
  const [selectedArtigos, setSelectedArtigos] = useState<string[]>([]);
  const [fotoFile, setFotoFile] = useState<File | null>(null);
  const [fotoPreview, setFotoPreview] = useState<string | null>(null);

  const [formData, setFormData] = useState({
    nome: "",
    rg: "",
    cpf: "",
    data_nascimento: "",
    nome_mae: "",
    nome_pai: "",
    observacao: "",
  });

  useEffect(() => {
    fetchArtigos();
    if (pessoaId) {
      fetchPessoa();
    }
  }, [pessoaId]);

  const fetchArtigos = async () => {
    try {
      const data = await artigosAPI.getAll();
      // Sort by numero
      const sorted = (data || []).sort((a, b) => a.numero.localeCompare(b.numero));
      setArtigos(sorted);
    } catch (error) {
      toast.error("Erro ao carregar códigos");
    }
  };

  const fetchPessoa = async () => {
    if (!pessoaId) return;

    try {
      setLoading(true);
      const pessoa = await pessoasAPI.getById(pessoaId);

      setFormData({
        nome: pessoa.nome,
        rg: pessoa.rg,
        cpf: pessoa.cpf || "",
        data_nascimento: pessoa.data_nascimento || "",
        nome_mae: pessoa.nome_mae || "",
        nome_pai: pessoa.nome_pai || "",
        observacao: pessoa.observacao || "",
      });

      if (pessoa.foto_url) {
        setFotoPreview(pessoa.foto_url);
      }

      // Buscar artigos associados
      const allPessoasArtigos = await pessoasArtigosAPI.getAll();
      const pessoaArtigos = allPessoasArtigos
        .filter(pa => pa.pessoa_id === pessoaId)
        .map(pa => pa.artigo_id);
      setSelectedArtigos(pessoaArtigos);
    } catch (error: any) {
      toast.error("Erro ao carregar pessoa: " + error.message);
      navigate("/dashboard");
    } finally {
      setLoading(false);
    }
  };

  const handleFotoChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setFotoFile(file);
      const reader = new FileReader();
      reader.onloadend = () => {
        setFotoPreview(reader.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      // Validar campos obrigatórios
      pessoaSchema.parse(formData);
      
      if (selectedArtigos.length === 0) {
        toast.error("Selecione pelo menos um código");
        return;
      }

      setLoading(true);

      // Usar a foto como base64 data URL (para armazenamento local)
      let fotoUrl = fotoPreview;
      if (fotoFile) {
        fotoUrl = await new Promise((resolve) => {
          const reader = new FileReader();
          reader.onloadend = () => resolve(reader.result as string);
          reader.readAsDataURL(fotoFile);
        });
      }

      const now = new Date().toISOString();

      if (pessoaId) {
        // Atualizar pessoa existente
        await pessoasAPI.update(pessoaId, {
          nome: formData.nome,
          rg: formData.rg,
          cpf: formData.cpf || undefined,
          data_nascimento: formData.data_nascimento || undefined,
          nome_mae: formData.nome_mae || undefined,
          nome_pai: formData.nome_pai || undefined,
          observacao: formData.observacao || undefined,
          residencial: undefined,
          foto_url: fotoUrl || undefined,
          updated_at: now,
        });

        // Deletar artigos antigos
        const allPessoasArtigos = await pessoasArtigosAPI.getAll();
        const antigosArtigos = allPessoasArtigos.filter(pa => pa.pessoa_id === pessoaId);
        
        for (const artigo of antigosArtigos) {
          await pessoasArtigosAPI.delete(artigo.id);
        }

        // Inserir novos artigos
        for (const artigoId of selectedArtigos) {
          await pessoasArtigosAPI.create({
            id: generateUUID(),
            pessoa_id: pessoaId,
            artigo_id: artigoId,
            created_at: now,
          });
        }

        toast.success("Pessoa atualizada com sucesso!");
      } else {
        // Inserir nova pessoa
        const newPessoaId = generateUUID();
        await pessoasAPI.create({
          id: newPessoaId,
          nome: formData.nome,
          rg: formData.rg,
          cpf: formData.cpf || undefined,
          data_nascimento: formData.data_nascimento || undefined,
          nome_mae: formData.nome_mae || undefined,
          nome_pai: formData.nome_pai || undefined,
          observacao: formData.observacao || undefined,
          residencial: undefined,
          foto_url: fotoUrl || undefined,
          created_at: now,
          updated_at: now,
        });

        // Inserir relações com artigos
        for (const artigoId of selectedArtigos) {
          await pessoasArtigosAPI.create({
            id: generateUUID(),
            pessoa_id: newPessoaId,
            artigo_id: artigoId,
            created_at: now,
          });
        }

        toast.success("Pessoa cadastrada com sucesso!");
      }
      navigate("/dashboard");
    } catch (error: any) {
      if (error instanceof z.ZodError) {
        toast.error(error.errors[0].message);
      } else {
        toast.error("Erro ao cadastrar pessoa: " + error.message);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background p-4">
      <div className="container mx-auto max-w-2xl py-8">
        <Button
          variant="ghost"
          onClick={() => navigate("/dashboard")}
          className="mb-4 gap-2"
        >
          <ArrowLeft className="h-4 w-4" />
          Voltar
        </Button>

        <Card>
          <CardHeader>
            <CardTitle>{pessoaId ? "Editar Pessoa" : "Cadastrar Nova Pessoa"}</CardTitle>
            <CardDescription>
              Preencha os dados da pessoa. Campos com * são obrigatórios.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Foto */}
              <div className="space-y-2">
                <Label>Foto</Label>
                {fotoPreview ? (
                  <div className="relative inline-block">
                    <img
                      src={fotoPreview}
                      alt="Preview"
                      className="w-32 h-32 rounded-lg object-cover border-2 border-border"
                    />
                    <Button
                      type="button"
                      variant="destructive"
                      size="sm"
                      className="absolute -top-2 -right-2"
                      onClick={() => {
                        setFotoFile(null);
                        setFotoPreview(null);
                      }}
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                ) : (
                  <div className="flex items-center gap-4">
                    <Input
                      id="foto"
                      type="file"
                      accept="image/*"
                      onChange={handleFotoChange}
                      className="hidden"
                    />
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => document.getElementById("foto")?.click()}
                      className="gap-2"
                    >
                      <Upload className="h-4 w-4" />
                      Escolher foto
                    </Button>
                  </div>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="nome">Nome *</Label>
                <Input
                  id="nome"
                  value={formData.nome}
                  onChange={(e) => setFormData({ ...formData, nome: e.target.value })}
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="rg">RG *</Label>
                  <InputMask
                    mask="99.999.999-9"
                    value={formData.rg}
                    onChange={(e) => setFormData({ ...formData, rg: e.target.value })}
                  >
                    {(inputProps: any) => (
                      <Input
                        {...inputProps}
                        id="rg"
                        placeholder="00.000.000-0"
                        required
                      />
                    )}
                  </InputMask>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="cpf">CPF</Label>
                  <InputMask
                    mask="999.999.999-99"
                    value={formData.cpf}
                    onChange={(e) => setFormData({ ...formData, cpf: e.target.value })}
                  >
                    {(inputProps: any) => (
                      <Input
                        {...inputProps}
                        id="cpf"
                        placeholder="000.000.000-00"
                      />
                    )}
                  </InputMask>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="data_nascimento">Data de Nascimento</Label>
                <Input
                  id="data_nascimento"
                  type="date"
                  value={formData.data_nascimento}
                  onChange={(e) =>
                    setFormData({ ...formData, data_nascimento: e.target.value })
                  }
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="nome_mae">Nome da Mãe</Label>
                  <Input
                    id="nome_mae"
                    value={formData.nome_mae}
                    onChange={(e) =>
                      setFormData({ ...formData, nome_mae: e.target.value })
                    }
                    placeholder="Nome completo da mãe"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="nome_pai">Nome do Pai</Label>
                  <Input
                    id="nome_pai"
                    value={formData.nome_pai}
                    onChange={(e) =>
                      setFormData({ ...formData, nome_pai: e.target.value })
                    }
                    placeholder="Nome completo do pai"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="observacao">Observações</Label>
                <Textarea
                  id="observacao"
                  value={formData.observacao}
                  onChange={(e) =>
                    setFormData({ ...formData, observacao: e.target.value })
                  }
                  placeholder="Observações adicionais sobre a pessoa"
                  rows={4}
                />
              </div>

              <div className="space-y-3">
                <Label>Código * (selecione pelo menos um)</Label>
                {artigos.length === 0 ? (
                  <p className="text-sm text-muted-foreground">
                    Nenhum código cadastrado.{" "}
                    <Button
                      type="button"
                      variant="link"
                      className="p-0 h-auto"
                      onClick={() => navigate("/cadastrar-artigo")}
                    >
                      Cadastrar código
                    </Button>
                  </p>
                ) : (
                  <div className="border rounded-lg p-4 space-y-3 max-h-60 overflow-y-auto">
                    {artigos.map((artigo) => (
                      <div key={artigo.id} className="flex items-center space-x-2">
                        <Checkbox
                          id={artigo.id}
                          checked={selectedArtigos.includes(artigo.id)}
                          onCheckedChange={(checked) => {
                            if (checked) {
                              setSelectedArtigos([...selectedArtigos, artigo.id]);
                            } else {
                              setSelectedArtigos(
                                selectedArtigos.filter((id) => id !== artigo.id)
                              );
                            }
                          }}
                        />
                        <label
                          htmlFor={artigo.id}
                          className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
                        >
                          {artigo.numero} - {artigo.nome}
                        </label>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="flex gap-4">
                <Button type="submit" disabled={loading} className="flex-1">
                  {loading ? "Salvando..." : pessoaId ? "Atualizar Pessoa" : "Salvar Pessoa"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => navigate("/dashboard")}
                >
                  Cancelar
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default CadastrarPessoa;
