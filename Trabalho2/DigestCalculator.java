// Gabriel de Barros Arruda - 2311723
// Érica Oliveira Regnier - 2211893

import java.io.*;
import java.security.*;
import java.util.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;

public class DigestCalculator {

    static final String STATUS_OK        = "OK";
    static final String STATUS_NOT_OK    = "NOT OK";
    static final String STATUS_NOT_FOUND = "NOT FOUND";
    static final String STATUS_COLISION  = "COLISION";

    public static void main (String[] args) throws Exception {
        int codigo = executa(args, System.out, System.err);
        if (codigo != 0) {
            System.exit(codigo);
        }
    }

    static int executa(String[] args, PrintStream out, PrintStream err) throws Exception {
        //
        // verifica args
        if (args.length != 3) {
            imprimeUso(err);
            return 1;
        }
        String tipoDigest = args[0].trim().toUpperCase();
        String algoritmo = nomeAlgoritmo(tipoDigest);
        if (algoritmo == null) {
            err.println("Tipo de digest invalido: " + args[0]);
            imprimeUso(err);
            return 1;
        }
        File arqListaDigest = new File(args[1]);
        File pasta = new File(args[2]);
        if (!pasta.isDirectory()) {
            err.println("Pasta dos arquivos invalida: " + args[2]);
            imprimeUso(err);
            return 1;
        }
        if (arqListaDigest.isDirectory()) {
            err.println("Arquivo da lista de digests invalido: " + args[1]);
            imprimeUso(err);
            return 1;
        }

        Map<String, Map<String, String>> catalogo;
        try {
            catalogo = leCatalogo(arqListaDigest);
        } catch (Exception e) {
            err.println("Erro ao ler o arquivo da lista de digests: " + e.getMessage());
            return 1;
        }
        //
        // define o objeto messageDigest com o algoritmo solicitado
        MessageDigest messageDigest = MessageDigest.getInstance(algoritmo);

        File[] conteudoPasta = pasta.listFiles();
        if (conteudoPasta == null) {
            err.println("Nao foi possivel listar a pasta: " + args[2]);
            return 1;
        }
        List<File> arquivos = new ArrayList<File>();
        for (File f : conteudoPasta) {
            if (f.isFile()) {
                arquivos.add(f);
            }
        }
        Collections.sort(arquivos, new Comparator<File>() {
            public int compare(File a, File b) {
                return a.getName().compareTo(b.getName());
            }
        });
        if (arquivos.isEmpty()) {
            err.println("Nenhum arquivo encontrado na pasta: " + args[2]);
            return 0;
        }
        //
        // calcula o digest do conteudo de cada arquivo
        Map<String, String> digestsCalculados = new LinkedHashMap<String, String>();
        for (File arq : arquivos) {
            byte[] digest = calculaDigest(messageDigest, arq);
            digestsCalculados.put(arq.getName(), toHex(digest));
        }

        List<String> arquivosNotFound = new ArrayList<String>();
        for (Map.Entry<String, String> entrada : digestsCalculados.entrySet()) {
            String nomeArq = entrada.getKey();
            String digestHex = entrada.getValue();
            String status = verificaStatus(nomeArq, digestHex, tipoDigest,
                                           digestsCalculados, catalogo);
            if (status.equals(STATUS_NOT_FOUND)) {
                arquivosNotFound.add(nomeArq);
            }
            out.println(nomeArq + " " + tipoDigest + " " + digestHex + " (" + status + ")");
        }

        if (!arquivosNotFound.isEmpty()) {
            for (String nomeArq : arquivosNotFound) {
                Map<String, String> digestsArq = catalogo.get(nomeArq);
                if (digestsArq == null) {
                    digestsArq = new LinkedHashMap<String, String>();
                    catalogo.put(nomeArq, digestsArq);
                }
                digestsArq.put(tipoDigest, digestsCalculados.get(nomeArq));
            }
            try {
                gravaCatalogo(arqListaDigest, catalogo);
            } catch (IOException e) {
                err.println("Erro ao gravar o arquivo da lista de digests: " + e.getMessage());
                return 1;
            }
        }
        return 0;
    }

    private static void imprimeUso(PrintStream err) {
        err.println("Usage: java DigestCalculator Tipo_Digest Caminho_ArqListaDigest Caminho_da_Pasta_dos_Arquivos");
        err.println("       Tipo_Digest: MD5 | SHA1 | SHA256 | SHA512");
    }

    static String nomeAlgoritmo(String tipoDigest) {
        if (tipoDigest.equals("MD5"))    return "MD5";
        if (tipoDigest.equals("SHA1"))   return "SHA-1";
        if (tipoDigest.equals("SHA256")) return "SHA-256";
        if (tipoDigest.equals("SHA512")) return "SHA-512";
        return null;
    }


    static byte[] calculaDigest(MessageDigest messageDigest, File arq) throws IOException {
        messageDigest.reset();
        byte[] buffer = new byte[8192];
        int lidos;
        FileInputStream in = new FileInputStream(arq);
        try {
            while ((lidos = in.read(buffer)) != -1) {
                messageDigest.update(buffer, 0, lidos);
            }
        } finally {
            in.close();
        }
        return messageDigest.digest();
    }

    static String toHex(byte[] digest) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            String hex = Integer.toHexString(0x0100 + (digest[i] & 0x00FF)).substring(1);
            buf.append((hex.length() < 2 ? "0" : "") + hex);
        }
        return buf.toString();
    }

    //
    // determina o status (OK, NOT OK, NOT FOUND ou COLISION) do digest de um arquivo
    static String verificaStatus(String nomeArq, String digestHex, String tipoDigest,
                                         Map<String, String> digestsCalculados,
                                         Map<String, Map<String, String>> catalogo) {
        for (Map.Entry<String, String> entrada : digestsCalculados.entrySet()) {
            if (!entrada.getKey().equals(nomeArq) && entrada.getValue().equalsIgnoreCase(digestHex)) {
                return STATUS_COLISION;
            }
        }

        for (Map.Entry<String, Map<String, String>> entrada : catalogo.entrySet()) {
            if (!entrada.getKey().equals(nomeArq)) {
                String digestConhecido = entrada.getValue().get(tipoDigest);
                if (digestConhecido != null && digestConhecido.equalsIgnoreCase(digestHex)) {
                    return STATUS_COLISION;
                }
            }
        }

        Map<String, String> digestsArq = catalogo.get(nomeArq);
        if (digestsArq == null || !digestsArq.containsKey(tipoDigest)) {
            return STATUS_NOT_FOUND;
        }
        if (digestsArq.get(tipoDigest).equalsIgnoreCase(digestHex)) {
            return STATUS_OK;
        }
        return STATUS_NOT_OK;
    }

    static Map<String, Map<String, String>> leCatalogo(File arqListaDigest) throws Exception {
        Map<String, Map<String, String>> catalogo = new LinkedHashMap<String, Map<String, String>>();

        if (!arqListaDigest.exists() || arqListaDigest.length() == 0) {
            return catalogo;
        }

        // Define o parser XML sem processamento de DTD/entidades externas 
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setExpandEntityReferences(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        // Erros de XML viram excecao, sem a impressao padrao "[Fatal Error]" do parser
        builder.setErrorHandler(new org.xml.sax.helpers.DefaultHandler());
        Document doc = builder.parse(arqListaDigest);

        Element raiz = doc.getDocumentElement();
        if (!raiz.getTagName().equals("CATALOG")) {
            throw new IOException("tag raiz deve ser <CATALOG>");
        }
        NodeList fileEntries = raiz.getElementsByTagName("FILE_ENTRY");
        for (int i = 0; i < fileEntries.getLength(); i++) {
            Element fileEntry = (Element) fileEntries.item(i);
            String nomeArq = textoFilho(fileEntry, "FILE_NAME");
            if (nomeArq == null) {
                continue;
            }
            Map<String, String> digestsArq = catalogo.get(nomeArq);
            if (digestsArq == null) {
                digestsArq = new LinkedHashMap<String, String>();
                catalogo.put(nomeArq, digestsArq);
            }
            NodeList digestEntries = fileEntry.getElementsByTagName("DIGEST_ENTRY");
            for (int j = 0; j < digestEntries.getLength(); j++) {
                Element digestEntry = (Element) digestEntries.item(j);
                String tipo = textoFilho(digestEntry, "DIGEST_TYPE");
                String hex = textoFilho(digestEntry, "DIGEST_HEX");
                if (tipo != null && hex != null && !digestsArq.containsKey(tipo.toUpperCase())) {
                    digestsArq.put(tipo.toUpperCase(), hex.toLowerCase());
                }
            }
        }
        return catalogo;
    }

    private static String textoFilho(Element pai, String tag) {
        NodeList nos = pai.getElementsByTagName(tag);
        if (nos.getLength() == 0) {
            return null;
        }
        return nos.item(0).getTextContent().trim();
    }

    static void gravaCatalogo(File arqListaDigest,
                                      Map<String, Map<String, String>> catalogo) throws IOException {
        StringBuffer xml = new StringBuffer();
        xml.append("<CATALOG>\n");
        for (Map.Entry<String, Map<String, String>> fileEntry : catalogo.entrySet()) {
            xml.append("\t<FILE_ENTRY>\n");
            xml.append("\t\t<FILE_NAME>" + escapaXml(fileEntry.getKey()) + "</FILE_NAME>\n");
            for (Map.Entry<String, String> digestEntry : fileEntry.getValue().entrySet()) {
                xml.append("\t\t<DIGEST_ENTRY>\n");
                xml.append("\t\t\t<DIGEST_TYPE>" + escapaXml(digestEntry.getKey()) + "</DIGEST_TYPE>\n");
                xml.append("\t\t\t<DIGEST_HEX>" + escapaXml(digestEntry.getValue()) + "</DIGEST_HEX>\n");
                xml.append("\t\t</DIGEST_ENTRY>\n");
            }
            xml.append("\t</FILE_ENTRY>\n");
        }
        xml.append("</CATALOG>\n");

        Writer out = new OutputStreamWriter(new FileOutputStream(arqListaDigest), "UTF8");
        try {
            out.write(xml.toString());
        } finally {
            out.close();
        }
    }

    private static String escapaXml(String texto) {
        return texto.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&apos;");
    }
}
