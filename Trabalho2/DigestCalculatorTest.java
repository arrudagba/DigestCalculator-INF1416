import static org.junit.Assert.*;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.regex.*;
import javax.xml.parsers.*;
import org.junit.*;
import org.junit.rules.TemporaryFolder;
import org.w3c.dom.*;

//
// Testes unitarios do DigestCalculator (JUnit 4).
//
// Usa os arquivos de testes/dat e as listas de testes/xml. Cada teste copia os
// arquivos necessarios para uma pasta temporaria, pois o DigestCalculator altera
// a lista de digests. Deve ser executado a partir da pasta Trabalho2.
//
// Arquivos .dat:
//   Arquivo1.dat - texto
//   Arquivo2.dat - texto
//   Arquivo3.dat - mesmo conteudo do Arquivo1.dat (colisao entre arquivos da pasta)
//   Arquivo4.dat - texto
//   Arquivo5.dat - vazio (0 bytes)
//   Arquivo6.dat - binario de 20000 bytes (maior que o buffer de leitura de 8192 bytes)
public class DigestCalculatorTest {

    private static final File DIR_DAT = new File("testes/dat");
    private static final File DIR_XML = new File("testes/xml");

    private static final String[] TIPOS = {"MD5", "SHA1", "SHA256", "SHA512"};

    private static final String OK        = DigestCalculator.STATUS_OK;
    private static final String NOT_OK    = DigestCalculator.STATUS_NOT_OK;
    private static final String NOT_FOUND = DigestCalculator.STATUS_NOT_FOUND;
    private static final String COLISION  = DigestCalculator.STATUS_COLISION;

    // Nome_Arq<SP>Tipo_Digest<SP>Digest_Hex<SP>(STATUS)
    private static final Pattern LINHA = Pattern.compile(
        "^(.+) (MD5|SHA1|SHA256|SHA512) ([0-9a-f]+) \\((OK|NOT OK|NOT FOUND|COLISION)\\)$");

    //
    // digests de referencia dos arquivos .dat, gerados com md5sum, sha1sum,
    // sha256sum e sha512sum (implementacao independente da JCA)
    private static final Map<String, Map<String, String>> REFERENCIA =
        new HashMap<String, Map<String, String>>();

    static {
        referencia("Arquivo1.dat", "MD5", "4ba0aab272f9d02348134b87d9284e19");
        referencia("Arquivo1.dat", "SHA1", "78cafc09fb2d9d2ffb6d0b9c76abf03011acbfe3");
        referencia("Arquivo1.dat", "SHA256", "3fb7f14b7b0a5cd15b5fb5867d6cf29d56f9d5282be7014473d93d53c5d96e60");
        referencia("Arquivo1.dat", "SHA512", "63e390e1988941105c11bfaedd86fe61f2db37a2a044993d392ad90af921e2f742334a13adbde880c1716cc5b01f0a5eaf72592cc0c36a8f4606daf6ab11bbbb");
        referencia("Arquivo2.dat", "MD5", "55bf02d01cc42f0dd3dc2f1ce94103cc");
        referencia("Arquivo2.dat", "SHA1", "3511243dcd1c9f1dd0f60d726f2a29f816b4cba1");
        referencia("Arquivo2.dat", "SHA256", "f22942f45a571eede9254c35b7296eb6aaae29c053e2c35d533a936eb42fe4e0");
        referencia("Arquivo2.dat", "SHA512", "77af49cd22d394736f3e8f421a921213ffb8cafb4f90f49068c3d48af347a7f7c20a6fe848525e4a303175301871d94d4af83012c6111d04423a85d591332948");
        referencia("Arquivo3.dat", "MD5", "4ba0aab272f9d02348134b87d9284e19");
        referencia("Arquivo3.dat", "SHA1", "78cafc09fb2d9d2ffb6d0b9c76abf03011acbfe3");
        referencia("Arquivo3.dat", "SHA256", "3fb7f14b7b0a5cd15b5fb5867d6cf29d56f9d5282be7014473d93d53c5d96e60");
        referencia("Arquivo3.dat", "SHA512", "63e390e1988941105c11bfaedd86fe61f2db37a2a044993d392ad90af921e2f742334a13adbde880c1716cc5b01f0a5eaf72592cc0c36a8f4606daf6ab11bbbb");
        referencia("Arquivo4.dat", "MD5", "12e194f16be9996b42a497ec7a087290");
        referencia("Arquivo4.dat", "SHA1", "58bf166a9eb6492a4d2cc0634c4272f2e72dba9f");
        referencia("Arquivo4.dat", "SHA256", "39b362da218574bed0da7d7bce99d37300117dc941212dfda51fb684da72f547");
        referencia("Arquivo4.dat", "SHA512", "6d19eff893b227cd0ff5dbc71c9be47c09867c8f395939bfa95b3f491d3c36d8a1b7e391baade839c08f746b0be773a0df13ac611e626db1c5a60b49fe1285ad");
        referencia("Arquivo5.dat", "MD5", "d41d8cd98f00b204e9800998ecf8427e");
        referencia("Arquivo5.dat", "SHA1", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        referencia("Arquivo5.dat", "SHA256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        referencia("Arquivo5.dat", "SHA512", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
        referencia("Arquivo6.dat", "MD5", "420a33bca71c3ff5c4d1096376a4ac59");
        referencia("Arquivo6.dat", "SHA1", "aac0e10927cb31f6dc682f6ea554a9b0818d7aed");
        referencia("Arquivo6.dat", "SHA256", "f8aed270a592b255d90b04785c0b130a968ae204948fc2755db1861c810c6c83");
        referencia("Arquivo6.dat", "SHA512", "8768fc46b6f0df3bb373dbe0fae192a300714ffa3f694ef63317bda2051010bd7dee31411a0b590435fda18c0c508333e5387cc2254aaccf7d378b062fc80b79");
    }

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @BeforeClass
    public static void verificaArquivosDeTeste() {
        assertTrue("Pasta " + DIR_DAT.getAbsolutePath() + " nao encontrada: execute os testes a partir da pasta Trabalho2",
                   DIR_DAT.isDirectory());
        assertTrue("Pasta " + DIR_XML.getAbsolutePath() + " nao encontrada: execute os testes a partir da pasta Trabalho2",
                   DIR_XML.isDirectory());
    }

    // =====================================================================
    // Observacao 5: argumentos omitidos, insuficientes ou invalidos
    // =====================================================================

    @Test
    public void semArgumentosImprimeOrientacaoEEncerra() throws Exception {
        Execucao e = executa();
        assertUso(e);
    }

    @Test
    public void argumentosInsuficientesImprimeOrientacaoEEncerra() throws Exception {
        File pasta = pasta("Arquivo1.dat");
        File lista = listaInexistente();
        assertUso(executa("SHA256"));
        assertUso(executa("SHA256", lista.getPath()));
        assertUso(executa(lista.getPath(), pasta.getPath()));
        assertFalse("a lista nao deve ser criada", lista.exists());
    }

    @Test
    public void argumentosEmExcessoImprimeOrientacaoEEncerra() throws Exception {
        File pasta = pasta("Arquivo1.dat");
        File lista = listaInexistente();
        assertUso(executa("SHA256", lista.getPath(), pasta.getPath(), "extra"));
        assertFalse("a lista nao deve ser criada", lista.exists());
    }

    @Test
    public void tipoDeDigestInvalidoImprimeOrientacaoEEncerra() throws Exception {
        File pasta = pasta("Arquivo1.dat");
        File lista = listaInexistente();
        for (String tipo : new String[] {"SHA3", "SHA-256", "SHA-1", "MD2", "SHA384", "SHA", ""}) {
            Execucao e = executa(tipo, lista.getPath(), pasta.getPath());
            assertUso(e);
            assertTrue("tipo " + tipo, e.erro.contains("Tipo de digest invalido"));
        }
        assertFalse("a lista nao deve ser criada", lista.exists());
    }

    @Test
    public void tipoDeDigestEmMinusculasEhAceito() throws Exception {
        File pasta = pasta("Arquivo1.dat");
        for (String tipo : TIPOS) {
            Execucao e = executa(tipo, listaInexistente(), pasta, tipo.toLowerCase());
            assertEquals(mapa("Arquivo1.dat", NOT_FOUND), e.status);
        }
    }

    @Test
    public void pastaInexistenteImprimeOrientacaoEEncerra() throws Exception {
        File lista = listaInexistente();
        Execucao e = executa("SHA256", lista.getPath(), new File(tmp.getRoot(), "nao_existe").getPath());
        assertUso(e);
        assertTrue(e.erro.contains("Pasta dos arquivos invalida"));
        assertFalse(lista.exists());
    }

    @Test
    public void pastaQueEhUmArquivoImprimeOrientacaoEEncerra() throws Exception {
        File pasta = pasta("Arquivo1.dat");
        Execucao e = executa("SHA256", listaInexistente().getPath(), new File(pasta, "Arquivo1.dat").getPath());
        assertUso(e);
        assertTrue(e.erro.contains("Pasta dos arquivos invalida"));
    }

    @Test
    public void listaQueEhUmaPastaImprimeOrientacaoEEncerra() throws Exception {
        File pasta = pasta("Arquivo1.dat");
        Execucao e = executa("SHA256", tmp.newFolder().getPath(), pasta.getPath());
        assertUso(e);
        assertTrue(e.erro.contains("Arquivo da lista de digests invalido"));
    }

    // =====================================================================
    // Passo 1: calculo dos digests (Observacoes 3 e 4)
    // =====================================================================

    @Test
    public void calculaOsQuatroTiposDeDigestParaTodosOsArquivos() throws Exception {
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo3.dat",
                           "Arquivo4.dat", "Arquivo5.dat", "Arquivo6.dat");
        for (String tipo : TIPOS) {
            // executa() confere cada digest impresso com o valor de referencia
            Execucao e = executa(tipo, listaInexistente(), pasta);
            assertEquals(6, e.linhas.size());
            for (String nomeArq : e.digest.keySet()) {
                assertEquals(tipo + " " + nomeArq, REFERENCIA.get(nomeArq).get(tipo), e.digest.get(nomeArq));
            }
        }
    }

    @Test
    public void tamanhoDoDigestHexadecimalCorrespondeAoTipo() throws Exception {
        File pasta = pasta("Arquivo1.dat");
        int[] bits = {128, 160, 256, 512};
        for (int i = 0; i < TIPOS.length; i++) {
            Execucao e = executa(TIPOS[i], listaInexistente(), pasta);
            assertEquals(TIPOS[i], bits[i] / 4, e.digest.get("Arquivo1.dat").length());
        }
    }

    @Test
    public void digestEhCalculadoSobreOConteudoENaoSobreONome() throws Exception {
        File pasta = pasta("Arquivo1.dat", "Arquivo3.dat");
        for (String tipo : TIPOS) {
            Execucao e = executa(tipo, listaInexistente(), pasta);
            // nomes diferentes e mesmo conteudo -> mesmo digest
            assertEquals(e.digest.get("Arquivo1.dat"), e.digest.get("Arquivo3.dat"));
            // o digest nao eh o do nome do arquivo
            MessageDigest md = MessageDigest.getInstance(DigestCalculator.nomeAlgoritmo(tipo));
            String digestDoNome = DigestCalculator.toHex(md.digest("Arquivo1.dat".getBytes("UTF8")));
            assertFalse(digestDoNome.equals(e.digest.get("Arquivo1.dat")));
        }
    }

    @Test
    public void digestDeArquivoVazio() throws Exception {
        File pasta = pasta("Arquivo5.dat");
        assertEquals(0, new File(pasta, "Arquivo5.dat").length());
        assertEquals("d41d8cd98f00b204e9800998ecf8427e",
                     executa("MD5", listaInexistente(), pasta).digest.get("Arquivo5.dat"));
        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709",
                     executa("SHA1", listaInexistente(), pasta).digest.get("Arquivo5.dat"));
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                     executa("SHA256", listaInexistente(), pasta).digest.get("Arquivo5.dat"));
        assertEquals("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                     executa("SHA512", listaInexistente(), pasta).digest.get("Arquivo5.dat"));
    }

    @Test
    public void digestDeArquivoMaiorQueOBufferDeLeitura() throws Exception {
        File arq = new File(DIR_DAT, "Arquivo6.dat");
        // 20000 bytes: mais de um bloco de 8192 e o ultimo bloco incompleto
        assertTrue(arq.length() > 8192);
        assertTrue(arq.length() % 8192 != 0);
        byte[] conteudo = Files.readAllBytes(arq.toPath());
        for (String tipo : TIPOS) {
            MessageDigest md = MessageDigest.getInstance(DigestCalculator.nomeAlgoritmo(tipo));
            String emBlocos = DigestCalculator.toHex(DigestCalculator.calculaDigest(md, arq));
            String deUmaVez = DigestCalculator.toHex(md.digest(conteudo));
            assertEquals(tipo, deUmaVez, emBlocos);
            assertEquals(tipo, REFERENCIA.get("Arquivo6.dat").get(tipo), emBlocos);
        }
    }

    @Test
    public void calculaDigestDescartaDadosAnterioresDoMessageDigest() throws Exception {
        for (String tipo : TIPOS) {
            MessageDigest md = MessageDigest.getInstance(DigestCalculator.nomeAlgoritmo(tipo));
            md.update("dados de um calculo anterior".getBytes("UTF8"));
            byte[] digest = DigestCalculator.calculaDigest(md, new File(DIR_DAT, "Arquivo1.dat"));
            assertEquals(tipo, REFERENCIA.get("Arquivo1.dat").get(tipo), DigestCalculator.toHex(digest));
        }
    }

    @Test
    public void toHexMantemOsZerosAEsquerda() {
        byte[] bytes = {(byte) 0x00, (byte) 0x01, (byte) 0x0f, (byte) 0x10, (byte) 0x7f, (byte) 0x80, (byte) 0xff};
        assertEquals("00010f107f80ff", DigestCalculator.toHex(bytes));
        assertEquals("", DigestCalculator.toHex(new byte[0]));
    }

    @Test
    public void tiposDoTrabalhoCorrespondemAosAlgoritmosDaJCA() {
        assertEquals("MD5", DigestCalculator.nomeAlgoritmo("MD5"));
        assertEquals("SHA-1", DigestCalculator.nomeAlgoritmo("SHA1"));
        assertEquals("SHA-256", DigestCalculator.nomeAlgoritmo("SHA256"));
        assertEquals("SHA-512", DigestCalculator.nomeAlgoritmo("SHA512"));
        assertNull(DigestCalculator.nomeAlgoritmo("SHA-256"));
        assertNull(DigestCalculator.nomeAlgoritmo("SHA3"));
    }

    // =====================================================================
    // Passo 3: formato da saida
    // =====================================================================

    @Test
    public void saidaTemUmaLinhaPorArquivoNoFormatoPedido() throws Exception {
        File pasta = pasta("Arquivo6.dat", "Arquivo2.dat", "Arquivo5.dat", "Arquivo1.dat", "Arquivo4.dat");
        // subpastas nao sao arquivos da pasta e sao ignoradas
        File subpasta = new File(pasta, "subpasta");
        assertTrue(subpasta.mkdir());
        Files.copy(new File(DIR_DAT, "Arquivo3.dat").toPath(), new File(subpasta, "Arquivo3.dat").toPath());

        for (String tipo : TIPOS) {
            Execucao e = executa(tipo, listaInexistente(), pasta);
            assertEquals(0, e.codigo);
            assertEquals(5, e.linhas.size());
            assertEquals(Arrays.asList("Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat", "Arquivo5.dat", "Arquivo6.dat"),
                         new ArrayList<String>(e.status.keySet()));
            for (String linha : e.linhas) {
                // nome sem o caminho da pasta
                assertFalse(linha, linha.contains(pasta.getPath()));
                assertFalse(linha, linha.contains(File.separator));
                String nomeArq = linha.substring(0, linha.indexOf(' '));
                assertEquals(nomeArq + " " + tipo + " " + REFERENCIA.get(nomeArq).get(tipo) + " (NOT FOUND)", linha);
            }
        }
    }

    @Test
    public void pastaVaziaNaoImprimeNadaENaoCriaALista() throws Exception {
        File lista = listaInexistente();
        Execucao e = executa("SHA256", lista.getPath(), tmp.newFolder().getPath());
        assertEquals(0, e.codigo);
        assertEquals("", e.saida);
        assertTrue(e.erro.contains("Nenhum arquivo encontrado"));
        assertFalse(lista.exists());
    }

    // =====================================================================
    // Passos 2 e 3: status de cada arquivo
    // =====================================================================

    @Test
    public void statusOkParaOsQuatroTipos() throws Exception {
        // lista_completa.xml: Arquivo1,2,4,5,6 com os 4 digests corretos, em ordens diferentes
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat", "Arquivo5.dat", "Arquivo6.dat");
        for (String tipo : TIPOS) {
            File lista = lista("lista_completa.xml");
            Execucao e = executa(tipo, lista, pasta);
            assertEquals(tipo, mapa("Arquivo1.dat", OK, "Arquivo2.dat", OK, "Arquivo4.dat", OK,
                                    "Arquivo5.dat", OK, "Arquivo6.dat", OK), e.status);
            assertListaInalterada("lista_completa.xml", lista);
        }
    }

    @Test
    public void statusComAListaDoExemploDoEnunciado() throws Exception {
        // lista_exemplo_enunciado.xml: Arquivo1 com SHA1 (com espaco antes do hex) e MD5;
        // Arquivo2 somente com SHA256
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat");
        assertEquals(mapa("Arquivo1.dat", OK, "Arquivo2.dat", NOT_FOUND),
                     executa("SHA1", lista("lista_exemplo_enunciado.xml"), pasta).status);
        assertEquals(mapa("Arquivo1.dat", OK, "Arquivo2.dat", NOT_FOUND),
                     executa("MD5", lista("lista_exemplo_enunciado.xml"), pasta).status);
        assertEquals(mapa("Arquivo1.dat", NOT_FOUND, "Arquivo2.dat", OK),
                     executa("SHA256", lista("lista_exemplo_enunciado.xml"), pasta).status);
        assertEquals(mapa("Arquivo1.dat", NOT_FOUND, "Arquivo2.dat", NOT_FOUND),
                     executa("SHA512", lista("lista_exemplo_enunciado.xml"), pasta).status);
    }

    @Test
    public void statusOkComHexEmMaiusculasEEspacosNaLista() throws Exception {
        // lista_formato_livre.xml: hex em maiusculas, espacos e quebras de linha,
        // tags fora de ordem e XML sem indentacao
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat");
        for (String tipo : TIPOS) {
            File lista = lista("lista_formato_livre.xml");
            assertEquals(tipo, mapa("Arquivo1.dat", OK, "Arquivo2.dat", OK), executa(tipo, lista, pasta).status);
            assertListaInalterada("lista_formato_livre.xml", lista);
        }
    }

    @Test
    public void statusNotOkParaOsQuatroTiposSemAlterarALista() throws Exception {
        // lista_incorreta.xml: Arquivo1,2,4,5,6 com os 4 digests incorretos
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat", "Arquivo5.dat", "Arquivo6.dat");
        for (String tipo : TIPOS) {
            File lista = lista("lista_incorreta.xml");
            Execucao e = executa(tipo, lista, pasta);
            assertEquals(tipo, mapa("Arquivo1.dat", NOT_OK, "Arquivo2.dat", NOT_OK, "Arquivo4.dat", NOT_OK,
                                    "Arquivo5.dat", NOT_OK, "Arquivo6.dat", NOT_OK), e.status);
            // o digest registrado nao eh substituido pelo calculado
            assertListaInalterada("lista_incorreta.xml", lista);
        }
    }

    @Test
    public void statusNotFoundQuandoOArquivoNaoEstaNaLista() throws Exception {
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat", "Arquivo5.dat", "Arquivo6.dat");
        Map<String, String> esperado = mapa("Arquivo1.dat", NOT_FOUND, "Arquivo2.dat", NOT_FOUND,
                                            "Arquivo4.dat", NOT_FOUND, "Arquivo5.dat", NOT_FOUND,
                                            "Arquivo6.dat", NOT_FOUND);
        for (String tipo : TIPOS) {
            assertEquals(tipo, esperado, executa(tipo, lista("lista_vazia.xml"), pasta).status);
            assertEquals(tipo, esperado, executa(tipo, lista("lista_sem_linhas.xml"), pasta).status);
            assertEquals(tipo, esperado, executa(tipo, listaInexistente(), pasta).status);
        }
    }

    @Test
    public void statusNotFoundQuandoOArquivoEstaNaListaSemOTipoPedido() throws Exception {
        // lista_um_digest_por_tipo.xml: Arquivo1 so MD5, Arquivo2 so SHA1,
        // Arquivo4 so SHA256, Arquivo5 so SHA512 e Arquivo6 ausente
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat", "Arquivo5.dat", "Arquivo6.dat");
        String[] arquivoComOTipo = {"Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat", "Arquivo5.dat"};
        for (int i = 0; i < TIPOS.length; i++) {
            Map<String, String> esperado = mapa("Arquivo1.dat", NOT_FOUND, "Arquivo2.dat", NOT_FOUND,
                                                "Arquivo4.dat", NOT_FOUND, "Arquivo5.dat", NOT_FOUND,
                                                "Arquivo6.dat", NOT_FOUND);
            esperado.put(arquivoComOTipo[i], OK);
            assertEquals(TIPOS[i], esperado, executa(TIPOS[i], lista("lista_um_digest_por_tipo.xml"), pasta).status);
        }
    }

    @Test
    public void statusColisionEntreArquivosDaPasta() throws Exception {
        // Arquivo1.dat e Arquivo3.dat tem o mesmo conteudo
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo3.dat");
        for (String tipo : TIPOS) {
            assertEquals(tipo, mapa("Arquivo1.dat", COLISION, "Arquivo2.dat", NOT_FOUND, "Arquivo3.dat", COLISION),
                         executa(tipo, lista("lista_vazia.xml"), pasta).status);
        }
    }

    @Test
    public void colisionEntreArquivosDaPastaPrevaleceSobreOk() throws Exception {
        // Arquivo1.dat esta correto na lista_completa.xml, mas colide com Arquivo3.dat
        File pasta = pasta("Arquivo1.dat", "Arquivo3.dat");
        for (String tipo : TIPOS) {
            File lista = lista("lista_completa.xml");
            assertEquals(tipo, mapa("Arquivo1.dat", COLISION, "Arquivo3.dat", COLISION),
                         executa(tipo, lista, pasta).status);
            assertListaInalterada("lista_completa.xml", lista);
        }
    }

    @Test
    public void statusColisionComArquivoDeOutroNomeNaLista() throws Exception {
        // lista_colisao_catalogo.xml:
        //   Arquivo2.dat correto + Arquivo2_copia.dat com os digests do Arquivo2 -> COLISION (e nao OK)
        //   Arquivo4.dat incorreto + Arquivo4_antigo.dat com os digests do Arquivo4 -> COLISION (e nao NOT OK)
        //   Arquivo6_renomeado.dat com os digests do Arquivo6 -> COLISION (e nao NOT FOUND)
        //   Arquivo5.dat correto -> OK;  Arquivo1.dat ausente -> NOT FOUND
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat", "Arquivo5.dat", "Arquivo6.dat");
        for (String tipo : TIPOS) {
            File lista = lista("lista_colisao_catalogo.xml");
            Execucao e = executa(tipo, lista, pasta);
            assertEquals(tipo, mapa("Arquivo1.dat", NOT_FOUND, "Arquivo2.dat", COLISION, "Arquivo4.dat", COLISION,
                                    "Arquivo5.dat", OK, "Arquivo6.dat", COLISION), e.status);
            // somente o NOT FOUND eh acrescentado
            Map<String, Map<String, String>> antes = DigestCalculator.leCatalogo(new File(DIR_XML, "lista_colisao_catalogo.xml"));
            Map<String, Map<String, String>> depois = DigestCalculator.leCatalogo(lista);
            antes.put("Arquivo1.dat", mapa(tipo, REFERENCIA.get("Arquivo1.dat").get(tipo)));
            assertEquals(tipo, antes, depois);
            assertFalse(depois.containsKey("Arquivo6.dat"));
        }
    }

    @Test
    public void osQuatroStatusNaMesmaExecucao() throws Exception {
        // lista_todos_status.xml + pasta com Arquivo1..6:
        //   Arquivo1/Arquivo3 -> COLISION (mesmo conteudo)   Arquivo2 -> OK
        //   Arquivo4 -> NOT OK   Arquivo5 -> NOT FOUND   Arquivo6 -> COLISION (Arquivo7.dat na lista)
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo3.dat",
                           "Arquivo4.dat", "Arquivo5.dat", "Arquivo6.dat");
        for (String tipo : TIPOS) {
            File lista = lista("lista_todos_status.xml");
            Execucao e = executa(tipo, lista, pasta);
            assertEquals(tipo, mapa("Arquivo1.dat", COLISION, "Arquivo2.dat", OK, "Arquivo3.dat", COLISION,
                                    "Arquivo4.dat", NOT_OK, "Arquivo5.dat", NOT_FOUND, "Arquivo6.dat", COLISION),
                         e.status);
            assertFormatoPadrao(lista);
        }
    }

    @Test
    public void verificaStatusDiretamente() {
        Map<String, Map<String, String>> catalogo = new LinkedHashMap<String, Map<String, String>>();
        catalogo.put("a.dat", mapa("SHA1", "aaaa"));
        catalogo.put("b.dat", mapa("SHA1", "bbbb", "MD5", "cccc"));
        Map<String, String> pasta = mapa("a.dat", "aaaa", "b.dat", "9999", "c.dat", "bbbb",
                                         "d.dat", "dddd", "e.dat", "eeee", "f.dat", "eeee");
        assertEquals(OK,        DigestCalculator.verificaStatus("a.dat", "AAAA", "SHA1", pasta, catalogo));
        assertEquals(NOT_OK,    DigestCalculator.verificaStatus("b.dat", "9999", "SHA1", pasta, catalogo));
        assertEquals(COLISION,  DigestCalculator.verificaStatus("c.dat", "bbbb", "SHA1", pasta, catalogo));
        assertEquals(NOT_FOUND, DigestCalculator.verificaStatus("d.dat", "dddd", "SHA1", pasta, catalogo));
        assertEquals(COLISION,  DigestCalculator.verificaStatus("e.dat", "eeee", "SHA1", pasta, catalogo));
        // mesmo valor registrado para outro tipo de digest nao eh colisao
        assertEquals(NOT_FOUND, DigestCalculator.verificaStatus("x.dat", "cccc", "SHA1",
                                                                mapa("x.dat", "cccc"), catalogo));
    }

    // =====================================================================
    // Passo 4: atualizacao da lista de digests
    // =====================================================================

    @Test
    public void notFoundDeArquivoNovoGeraEntradaNoFormatoPadrao() throws Exception {
        File pasta = pasta("Arquivo2.dat");
        File lista = lista("lista_vazia.xml");
        executa("SHA256", lista, pasta);
        assertEquals("<CATALOG>\n"
                   + "\t<FILE_ENTRY>\n"
                   + "\t\t<FILE_NAME>Arquivo2.dat</FILE_NAME>\n"
                   + "\t\t<DIGEST_ENTRY>\n"
                   + "\t\t\t<DIGEST_TYPE>SHA256</DIGEST_TYPE>\n"
                   + "\t\t\t<DIGEST_HEX>" + REFERENCIA.get("Arquivo2.dat").get("SHA256") + "</DIGEST_HEX>\n"
                   + "\t\t</DIGEST_ENTRY>\n"
                   + "\t</FILE_ENTRY>\n"
                   + "</CATALOG>\n", le(lista));
    }

    @Test
    public void notFoundDeArquivoNovoEhAcrescentadoNoFinalDaLista() throws Exception {
        File pasta = pasta("Arquivo1.dat", "Arquivo4.dat");
        File lista = lista("lista_exemplo_enunciado.xml");
        Execucao e = executa("SHA1", lista, pasta);
        assertEquals(mapa("Arquivo1.dat", OK, "Arquivo4.dat", NOT_FOUND), e.status);
        assertEquals(Arrays.asList("Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat"), nomesNaLista(lista));

        Map<String, Map<String, String>> esperado = DigestCalculator.leCatalogo(new File(DIR_XML, "lista_exemplo_enunciado.xml"));
        esperado.put("Arquivo4.dat", mapa("SHA1", REFERENCIA.get("Arquivo4.dat").get("SHA1")));
        assertEquals(esperado, DigestCalculator.leCatalogo(lista));
        assertFormatoPadrao(lista);
    }

    @Test
    public void notFoundDeArquivoJaListadoAcrescentaDigestNaEntradaExistente() throws Exception {
        // Arquivo1.dat ja tem SHA1 e MD5 na lista: o SHA256 entra no mesmo FILE_ENTRY
        File pasta = pasta("Arquivo1.dat");
        File lista = lista("lista_exemplo_enunciado.xml");
        assertEquals(mapa("Arquivo1.dat", NOT_FOUND), executa("SHA256", lista, pasta).status);
        assertEquals(Arrays.asList("Arquivo1.dat", "Arquivo2.dat"), nomesNaLista(lista));

        Map<String, Map<String, String>> catalogo = DigestCalculator.leCatalogo(lista);
        assertEquals(Arrays.asList("SHA1", "MD5", "SHA256"), new ArrayList<String>(catalogo.get("Arquivo1.dat").keySet()));
        assertEquals(REFERENCIA.get("Arquivo1.dat").get("SHA256"), catalogo.get("Arquivo1.dat").get("SHA256"));
        assertEquals(mapa("SHA256", REFERENCIA.get("Arquivo2.dat").get("SHA256")), catalogo.get("Arquivo2.dat"));
        assertFormatoPadrao(lista);
    }

    @Test
    public void colisionNaoEhAcrescentadoNaLista() throws Exception {
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo3.dat");
        for (String tipo : TIPOS) {
            File lista = lista("lista_vazia.xml");
            executa(tipo, lista, pasta);
            assertEquals(Arrays.asList("Arquivo2.dat"), nomesNaLista(lista));
        }
        // somente colisoes: a lista nao eh alterada
        File pastaColisao = pasta("Arquivo1.dat", "Arquivo3.dat");
        File lista = lista("lista_vazia.xml");
        executa("SHA256", lista, pastaColisao);
        assertListaInalterada("lista_vazia.xml", lista);
    }

    @Test
    public void listaInexistenteEhCriadaComOsNotFound() throws Exception {
        File pasta = pasta("Arquivo2.dat", "Arquivo4.dat");
        File lista = listaInexistente();
        executa("MD5", lista, pasta);
        assertTrue(lista.isFile());
        assertEquals(Arrays.asList("Arquivo2.dat", "Arquivo4.dat"), nomesNaLista(lista));
        assertFormatoPadrao(lista);
    }

    @Test
    public void listaSemLinhasRecebeOsNotFound() throws Exception {
        File pasta = pasta("Arquivo5.dat");
        File lista = lista("lista_sem_linhas.xml");
        assertEquals(0, lista.length());
        executa("SHA512", lista, pasta);
        assertEquals(mapa("SHA512", REFERENCIA.get("Arquivo5.dat").get("SHA512")),
                     DigestCalculator.leCatalogo(lista).get("Arquivo5.dat"));
        assertFormatoPadrao(lista);
    }

    @Test
    public void segundaExecucaoReconheceOsDigestsAcrescentados() throws Exception {
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo3.dat",
                           "Arquivo4.dat", "Arquivo5.dat", "Arquivo6.dat");
        for (String tipo : TIPOS) {
            File lista = lista("lista_todos_status.xml");
            assertEquals(NOT_FOUND, executa(tipo, lista, pasta).status.get("Arquivo5.dat"));
            String depoisDaPrimeira = le(lista);

            Execucao segunda = executa(tipo, lista, pasta);
            assertEquals(tipo, mapa("Arquivo1.dat", COLISION, "Arquivo2.dat", OK, "Arquivo3.dat", COLISION,
                                    "Arquivo4.dat", NOT_OK, "Arquivo5.dat", OK, "Arquivo6.dat", COLISION),
                         segunda.status);
            assertEquals("sem NOT FOUND a lista nao muda", depoisDaPrimeira, le(lista));
        }
    }

    @Test
    public void listaAcumulaAteQuatroDigestsUmDeCadaTipo() throws Exception {
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat", "Arquivo5.dat", "Arquivo6.dat");
        File lista = lista("lista_vazia.xml");
        for (String tipo : TIPOS) {
            executa(tipo, lista, pasta);
        }
        Map<String, Map<String, String>> catalogo = DigestCalculator.leCatalogo(lista);
        assertEquals(Arrays.asList("Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat", "Arquivo5.dat", "Arquivo6.dat"),
                     nomesNaLista(lista));
        for (String nomeArq : catalogo.keySet()) {
            assertEquals(Arrays.asList(TIPOS), new ArrayList<String>(catalogo.get(nomeArq).keySet()));
            assertEquals(REFERENCIA.get(nomeArq), catalogo.get(nomeArq));
        }
        assertFormatoPadrao(lista);
        // nova execucao de qualquer tipo: tudo OK e nenhum digest duplicado
        String completa = le(lista);
        for (String tipo : TIPOS) {
            Execucao e = executa(tipo, lista, pasta);
            assertEquals(tipo, mapa("Arquivo1.dat", OK, "Arquivo2.dat", OK, "Arquivo4.dat", OK,
                                    "Arquivo5.dat", OK, "Arquivo6.dat", OK), e.status);
            assertEquals(completa, le(lista));
        }
    }

    @Test
    public void listaEmFormatoLivreEhRegravadaNoFormatoPadrao() throws Exception {
        // lista_formato_livre.xml tem hex em maiusculas e espacos; o NOT FOUND do
        // Arquivo4.dat faz a lista ser regravada, preservando os digests existentes
        File pasta = pasta("Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat");
        File lista = lista("lista_formato_livre.xml");
        assertEquals(mapa("Arquivo1.dat", OK, "Arquivo2.dat", OK, "Arquivo4.dat", NOT_FOUND),
                     executa("SHA256", lista, pasta).status);
        assertFormatoPadrao(lista);
        Map<String, Map<String, String>> catalogo = DigestCalculator.leCatalogo(lista);
        assertEquals(Arrays.asList("Arquivo1.dat", "Arquivo2.dat", "Arquivo4.dat"), nomesNaLista(lista));
        assertEquals(REFERENCIA.get("Arquivo1.dat"), catalogo.get("Arquivo1.dat"));
        assertEquals(REFERENCIA.get("Arquivo2.dat"), catalogo.get("Arquivo2.dat"));
        assertEquals(mapa("SHA256", REFERENCIA.get("Arquivo4.dat").get("SHA256")), catalogo.get("Arquivo4.dat"));
    }

    @Test
    public void nomeDeArquivoComCaracterEspecialDoXml() throws Exception {
        File pasta = tmp.newFolder();
        Files.copy(new File(DIR_DAT, "Arquivo4.dat").toPath(), new File(pasta, "Arquivo&Cia.dat").toPath());
        File lista = lista("lista_vazia.xml");
        assertEquals(mapa("Arquivo&Cia.dat", NOT_FOUND), executa("MD5", lista, pasta).status);
        assertTrue(le(lista).contains("<FILE_NAME>Arquivo&amp;Cia.dat</FILE_NAME>"));
        assertFormatoPadrao(lista);
        assertEquals(mapa("Arquivo&Cia.dat", OK), executa("MD5", lista, pasta).status);
    }

    // =====================================================================
    // Listas de digests invalidas
    // =====================================================================

    @Test
    public void listaMalFormadaEncerraComErro() throws Exception {
        assertListaRejeitada("lista_mal_formada.xml");
    }

    @Test
    public void listaComRaizDiferenteDeCatalogEncerraComErro() throws Exception {
        assertListaRejeitada("lista_raiz_invalida.xml");
    }

    @Test
    public void listaComDoctypeEhRejeitada() throws Exception {
        // evita XXE: a entidade externa nao pode ser resolvida
        assertListaRejeitada("lista_com_doctype.xml");
    }

    // =====================================================================
    // Auxiliares
    // =====================================================================

    private static class Execucao {
        int codigo;
        String saida;
        String erro;
        List<String> linhas = new ArrayList<String>();
        Map<String, String> status = new LinkedHashMap<String, String>();   // nome -> status
        Map<String, String> digest = new LinkedHashMap<String, String>();   // nome -> digest hex
    }

    //
    // executa o DigestCalculator capturando a saida padrao e a saida de erro
    private Execucao executa(String... args) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        Execucao e = new Execucao();
        e.codigo = DigestCalculator.executa(args, new PrintStream(out, true, "UTF8"),
                                            new PrintStream(err, true, "UTF8"));
        e.saida = out.toString("UTF8");
        e.erro = err.toString("UTF8");
        for (String linha : e.saida.split("\\r?\\n")) {
            if (linha.isEmpty()) {
                continue;
            }
            Matcher m = LINHA.matcher(linha);
            assertTrue("linha fora do formato Nome_Arq Tipo_Digest Digest_Hex (STATUS): " + linha, m.matches());
            e.linhas.add(linha);
            e.status.put(m.group(1), m.group(4));
            e.digest.put(m.group(1), m.group(3));
        }
        return e;
    }

    //
    // executa com a linha de comando valida e confere o tipo e o digest de cada linha
    private Execucao executa(String tipo, File lista, File pasta) throws Exception {
        return executa(tipo, lista, pasta, tipo);
    }

    private Execucao executa(String tipo, File lista, File pasta, String argTipo) throws Exception {
        Execucao e = executa(argTipo, lista.getPath(), pasta.getPath());
        assertEquals("codigo de saida; erro: " + e.erro, 0, e.codigo);
        assertEquals("saida de erro", "", e.erro);
        for (String linha : e.linhas) {
            Matcher m = LINHA.matcher(linha);
            assertTrue(m.matches());
            assertEquals(linha, tipo, m.group(2));
            Map<String, String> ref = REFERENCIA.get(m.group(1));
            if (ref != null) {
                assertEquals("digest de " + m.group(1), ref.get(tipo), m.group(3));
            }
        }
        return e;
    }

    private void assertUso(Execucao e) {
        assertEquals(1, e.codigo);
        assertEquals("nada deve ir para a saida padrao", "", e.saida);
        assertTrue(e.erro, e.erro.contains("Usage: java DigestCalculator Tipo_Digest Caminho_ArqListaDigest Caminho_da_Pasta_dos_Arquivos"));
    }

    private void assertListaRejeitada(String xml) throws Exception {
        File lista = lista(xml);
        Execucao e = executa("MD5", lista.getPath(), pasta("Arquivo1.dat").getPath());
        assertEquals(1, e.codigo);
        assertEquals("", e.saida);
        assertTrue(e.erro, e.erro.contains("Erro ao ler o arquivo da lista de digests"));
        assertListaInalterada(xml, lista);
    }

    private void assertListaInalterada(String xml, File lista) throws IOException {
        assertEquals("a lista nao deveria ser alterada", le(new File(DIR_XML, xml)), le(lista));
    }

    //
    // confere o formato padrao da lista: CATALOG -> FILE_ENTRY* ->
    // (FILE_NAME, DIGEST_ENTRY de 1 a 4, um de cada tipo) -> (DIGEST_TYPE, DIGEST_HEX)
    private void assertFormatoPadrao(File lista) throws Exception {
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(lista);
        Element raiz = doc.getDocumentElement();
        assertEquals("CATALOG", raiz.getTagName());
        Set<String> nomes = new HashSet<String>();
        for (Element fileEntry : filhos(raiz)) {
            assertEquals("FILE_ENTRY", fileEntry.getTagName());
            List<Element> itens = filhos(fileEntry);
            assertEquals("FILE_NAME", itens.get(0).getTagName());
            assertTrue("FILE_NAME repetido", nomes.add(itens.get(0).getTextContent()));
            assertTrue("um ou mais DIGEST_ENTRY", itens.size() >= 2);
            assertTrue("no maximo 4 DIGEST_ENTRY", itens.size() <= 5);
            Set<String> tipos = new HashSet<String>();
            for (Element digestEntry : itens.subList(1, itens.size())) {
                assertEquals("DIGEST_ENTRY", digestEntry.getTagName());
                List<Element> campos = filhos(digestEntry);
                assertEquals(2, campos.size());
                assertEquals("DIGEST_TYPE", campos.get(0).getTagName());
                assertEquals("DIGEST_HEX", campos.get(1).getTagName());
                String tipo = campos.get(0).getTextContent();
                assertNotNull("tipo invalido: " + tipo, DigestCalculator.nomeAlgoritmo(tipo));
                assertTrue("tipo repetido: " + tipo, tipos.add(tipo));
                assertTrue(campos.get(1).getTextContent().matches("[0-9a-f]+"));
            }
        }
    }

    private static List<Element> filhos(Element pai) {
        List<Element> filhos = new ArrayList<Element>();
        NodeList nos = pai.getChildNodes();
        for (int i = 0; i < nos.getLength(); i++) {
            if (nos.item(i) instanceof Element) {
                filhos.add((Element) nos.item(i));
            }
        }
        return filhos;
    }

    private static List<String> nomesNaLista(File lista) throws Exception {
        return new ArrayList<String>(DigestCalculator.leCatalogo(lista).keySet());
    }

    //
    // cria uma pasta temporaria com copias dos arquivos .dat indicados
    private File pasta(String... dats) throws IOException {
        File pasta = tmp.newFolder();
        for (String dat : dats) {
            Files.copy(new File(DIR_DAT, dat).toPath(), new File(pasta, dat).toPath());
        }
        return pasta;
    }

    //
    // copia uma lista de testes/xml para uma pasta temporaria (fora da pasta dos arquivos)
    private File lista(String xml) throws IOException {
        File destino = new File(tmp.newFolder(), xml);
        Files.copy(new File(DIR_XML, xml).toPath(), destino.toPath());
        return destino;
    }

    private File listaInexistente() throws IOException {
        return new File(tmp.newFolder(), "lista_nova.xml");
    }

    private static String le(File arq) throws IOException {
        return new String(Files.readAllBytes(arq.toPath()), "UTF8");
    }

    private static Map<String, String> mapa(String... pares) {
        Map<String, String> m = new LinkedHashMap<String, String>();
        for (int i = 0; i < pares.length; i += 2) {
            m.put(pares[i], pares[i + 1]);
        }
        return m;
    }

    private static void referencia(String nomeArq, String tipo, String hex) {
        Map<String, String> digests = REFERENCIA.get(nomeArq);
        if (digests == null) {
            digests = new HashMap<String, String>();
            REFERENCIA.put(nomeArq, digests);
        }
        digests.put(tipo, hex);
    }
}
