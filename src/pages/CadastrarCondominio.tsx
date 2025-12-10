import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";
import { condominiosAPI, generateUUID } from "@/lib/api";

const CadastrarCondominio = () => {
  const navigate = useNavigate();
  const [nome, setNome] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!nome.trim()) {
      toast.error("Por favor, preencha o nome do condomínio");
      return;
    }

    setLoading(true);

    try {
      await condominiosAPI.create({
        id: generateUUID(),
        nome: nome.trim(),
        created_at: new Date().toISOString(),
      });

      toast.success("Condomínio cadastrado com sucesso!");
      setNome("");
      navigate("/dashboard");
    } catch (error: any) {
      console.error("Erro ao cadastrar condomínio:", error);
      toast.error(error.message || "Erro ao cadastrar condomínio");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background p-8">
      <div className="max-w-2xl mx-auto">
        <Button
          variant="ghost"
          onClick={() => navigate("/dashboard")}
          className="mb-4"
        >
          <ArrowLeft className="mr-2 h-4 w-4" />
          Voltar
        </Button>

        <Card>
          <CardHeader>
            <CardTitle>Cadastrar Condomínio</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="nome">Nome do Condomínio *</Label>
                <Input
                  id="nome"
                  value={nome}
                  onChange={(e) => setNome(e.target.value)}
                  placeholder="Digite o nome do condomínio"
                  required
                />
              </div>

              <Button type="submit" disabled={loading} className="w-full">
                {loading ? "Cadastrando..." : "Cadastrar Condomínio"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default CadastrarCondominio;
