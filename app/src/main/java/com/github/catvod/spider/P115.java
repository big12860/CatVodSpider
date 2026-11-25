package com.github.catvod.spider;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 115 网盘 SDK（纯 Java 移植自 Operit/py/p115.py 的 RSA 通道）。
 * 加密：PKCS1v1.5 + 115 专属 1024 位公钥 + 自定义 XOR 前缀，无 AES/ECDH/LZ4 依赖。
 * 凭证：/storage/emulated/0/tmp/auth/115_login.json {cookie,uid,app}
 */
public final class P115 {

    private static final String LOGIN_JSON = "/storage/emulated/0/tmp/auth/115_login.json";
    private static final String OFFLINE_API = "https://clouddownload.115.com/lixianssp/";
    private static final String DOWNURL_API = "https://proapi.115.com/app/chrome/downurl";
    private static final String FILES_API = "https://webapi.115.com/files";
    private static final String SEARCH_API = "https://webapi.115.com/files/search";
    private static final String UA = "Mozilla/5.0 115disk/36.2.28 115Browser/36.2.28 115wangpan_android/36.2.28";
    private static final String APP_VER = "36.2.28";
    private static final String[] VIDEO_EXT = {".mp4", ".mkv", ".avi", ".ts", ".mov", ".flv", ".wmv", ".rmvb", ".iso"};

    // 115 专属公钥 N / e
    private static final BigInteger N = new BigInteger(
            "8686980c0f5a24c4b9d43020cd2c22703ff3f450756529058b1cf88f09b8602136477198a6e2683149659bd122c33592fdb5ad47944ad1ea4d36c6b172aad6338c3bb6ac6227502d010993ac967d1aef00f0c8e038de2e4d3bc2ec368af2e9f10a6f1eda4f7262f136420c07c331b871bf139f74f3010e3c4fe57df3afb71683", 16);
    private static final BigInteger E = new BigInteger("10001", 16);
    private static final byte[] RSA_KEY = {(byte) 0x8d, (byte) 0xa5, (byte) 0xa5, (byte) 0x8d};
    private static final byte[] G_KEY_L = {0x78, 0x06, (byte) 0xad, 0x4c, 0x33, (byte) 0x86, 0x5d, 0x18, 0x4c, 0x01, 0x3f, 0x46};
    private static final byte[] G_KTS = {
            (byte)0xf0,(byte)0xe5,0x69,(byte)0xae,(byte)0xbf,(byte)0xdc,(byte)0xbf,(byte)0x8a,0x1a,0x45,(byte)0xe8,(byte)0xbe,0x7d,(byte)0xa6,0x73,(byte)0xb8,
            (byte)0xde,(byte)0x8f,(byte)0xe7,(byte)0xc4,0x45,(byte)0xda,(byte)0x86,(byte)0xc4,(byte)0x9b,0x64,(byte)0x8b,0x14,0x6a,(byte)0xb4,(byte)0xf1,(byte)0xaa,
            0x38,0x01,0x35,(byte)0x9e,0x26,0x69,0x2c,(byte)0x86,0x00,0x6b,0x4f,(byte)0xa5,0x36,0x34,0x62,(byte)0xa6,
            0x2a,(byte)0x96,0x68,0x18,(byte)0xf2,0x4a,(byte)0xfd,(byte)0xbd,0x6b,(byte)0x97,(byte)0x8f,0x4d,(byte)0x8f,(byte)0x89,0x13,(byte)0xb7,
            0x6c,(byte)0x8e,(byte)0x93,(byte)0xed,0x0e,0x0d,0x48,0x3e,(byte)0xd7,0x2f,(byte)0x88,(byte)0xd8,(byte)0xfe,(byte)0xfe,0x7e,(byte)0x86,
            0x50,(byte)0x95,0x4f,(byte)0xd1,(byte)0xeb,(byte)0x83,0x26,0x34,(byte)0xdb,0x66,0x7b,(byte)0x9c,0x7e,(byte)0x9d,0x7a,(byte)0x81,
            0x32,(byte)0xea,(byte)0xb6,0x33,(byte)0xde,0x3a,(byte)0xa9,0x59,0x34,0x66,0x3b,(byte)0xaa,(byte)0xba,(byte)0x81,0x60,0x48,
            (byte)0xb9,(byte)0xd5,(byte)0x81,(byte)0x9c,(byte)0xf8,0x6c,(byte)0x84,0x77,(byte)0xff,0x54,0x78,0x26,0x5f,(byte)0xbe,(byte)0xe8,0x1e,
            0x36,(byte)0x9f,0x34,(byte)0x80,0x5c,0x45,0x2c,(byte)0x9b,0x76,(byte)0xd5,0x1b,(byte)0x8f,(byte)0xcc,(byte)0xc3,(byte)0xb8,(byte)0xf5,
    };

    private P115() {}

    // ---------- 凭证 ----------
    private static String cookie = "";

    private static void loadCookie() {
        try {
            String s = readFile(LOGIN_JSON);
            if (s == null || s.isEmpty()) return;
            JSONObject d = new JSONObject(s);
            String c = d.optString("cookie", "");
            if (c.contains("UID=") && c.contains("CID=") && c.contains("SEID=")) cookie = c;
        } catch (Exception ignore) {
        }
    }

    private static String readFile(String path) {
        try {
            java.io.File f = new java.io.File(path);
            if (!f.exists()) return null;
            InputStream in = new java.io.FileInputStream(f);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            in.close();
            return new String(bos.toByteArray(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    // ---------- RSA 核心（逐字复刻 p115.py） ----------
    private static byte[] xor(byte[] src, byte[] key) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int len = key.length;
        int i = src.length & 0x03;
        if (i != 0) for (int j = 0; j < i; j++) out.write(src[j] ^ key[j]);
        int start = i;
        while (start < src.length) {
            int s = Math.min(start + len, src.length) - start;
            for (int j = 0; j < s; j++) out.write(src[start + j] ^ key[j]);
            start += len;
        }
        return out.toByteArray();
    }

    private static void reverse(byte[] a) {
        for (int i = 0, j = a.length - 1; i < j; i++, j--) {
            byte t = a[i]; a[i] = a[j]; a[j] = t;
        }
    }

    private static byte[] rsaGenKey(byte[] randKey, int skLen) {
        byte[] out = new byte[skLen];
        int length = skLen * (skLen - 1);
        int index = 0;
        for (int i = 0; i < skLen; i++) {
            int x = ((randKey[i] & 0xff) + (G_KTS[index] & 0xff)) & 0xff;
            out[i] = (byte) (G_KTS[length] ^ x);
            length -= skLen;
            index += skLen;
        }
        return out;
    }

    private static BigInteger padPkcs1(byte[] msg) {
        byte[] data = new byte[128];
        int padLen = 126 - msg.length;
        for (int i = 1; i <= padLen; i++) data[i] = 2;
        data[padLen + 1] = 0;
        System.arraycopy(msg, 0, data, padLen + 2, msg.length);
        return new BigInteger(1, data);
    }

    private static byte[] enc128(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[128];
        if (b.length <= 128) System.arraycopy(b, 0, out, 128 - b.length, b.length);
        else System.arraycopy(b, b.length - 128, out, 0, 128);
        return out;
    }

    private static byte[] rsaEncWithPub(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int start = 0; start < data.length; start += 117) {
            int len = Math.min(117, data.length - start);
            byte[] chunk = Arrays.copyOfRange(data, start, start + len);
            byte[] c = enc128(padPkcs1(chunk).modPow(E, N));
            out.write(c, 0, 128);
        }
        return out.toByteArray();
    }

    private static byte[] rsaDecWithPub(byte[] cipher) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int start = 0; start < cipher.length; start += 128) {
            int len = Math.min(128, cipher.length - start);
            byte[] chunk = Arrays.copyOfRange(cipher, start, start + len);
            BigInteger p = new BigInteger(1, chunk).modPow(E, N);
            byte[] b = p.toByteArray();
            int idx = 0;
            while (idx < b.length - 1 && b[idx] == 0) idx++;
            int zero = -1;
            for (int i = idx; i < b.length; i++) if (b[i] == 0) { zero = i; break; }
            if (zero >= 0) out.write(b, zero + 1, b.length - zero - 1);
        }
        return out.toByteArray();
    }

    private static String rsaEncrypt(String plain) throws Exception {
        byte[] data = plain.getBytes(StandardCharsets.UTF_8);
        byte[] tmp = xor(data, RSA_KEY);
        reverse(tmp);
        byte[] xd = xor(tmp, G_KEY_L);
        byte[] xorData = new byte[16 + xd.length]; // 前 16 字节 RSA_RAND_KEY = 0x00
        System.arraycopy(xd, 0, xorData, 16, xd.length);
        return Base64.getEncoder().encodeToString(rsaEncWithPub(xorData));
    }

    private static String rsaDecrypt(String cipher) throws Exception {
        byte[] data = rsaDecWithPub(Base64.getDecoder().decode(cipher));
        byte[] randkey = Arrays.copyOfRange(data, 0, 16);
        byte[] keyL = rsaGenKey(randkey, 12);
        byte[] rest = Arrays.copyOfRange(data, 16, data.length);
        byte[] tmp = xor(rest, keyL);
        reverse(tmp);
        return new String(xor(tmp, RSA_KEY), StandardCharsets.UTF_8);
    }

    // ---------- HTTP ----------
    private static String http(String method, String url, String body, String contentType) {
        HttpURLConnection conn = null;
        try {
            URL u = new URL(url);
            conn = (HttpURLConnection) u.openConnection();
            conn.setRequestMethod(method);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(20000);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("User-Agent", UA);
            if (!cookie.isEmpty()) {
                conn.setRequestProperty("Cookie", cookie);
                conn.setRequestProperty("Referer", "https://www.115.com/");
            }
            if (body != null) {
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", contentType);
                OutputStream os = conn.getOutputStream();
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
                os.close();
            }
            InputStream in = conn.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            br.close();
            return sb.toString();
        } catch (Exception e) {
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /** RSA POST + 响应解密，返回解密后的内层 JSONObject（失败 null）。 */
    private static JSONObject apiPostRsa(String url, JSONObject payload, int timeout) {
        try {
            String enc = rsaEncrypt(payload.toString());
            String form = "data=" + URLEncoder.encode(enc, "UTF-8");
            String resp = http("POST", url, form, "application/x-www-form-urlencoded");
            if (resp == null) return null;
            JSONObject js = new JSONObject(resp);
            String data = js.optString("data", "");
            if (data.isEmpty()) return null;
            return new JSONObject(rsaDecrypt(data));
        } catch (Exception e) {
            return null;
        }
    }

    private static String btihOf(String magnet) {
        if (magnet == null) return null;
        Matcher m = Pattern.compile("btih:([0-9a-fA-F]{40})").matcher(magnet);
        return m.find() ? m.group(1).toLowerCase() : null;
    }

    // ---------- 离线 ----------
    private static String queryFileId(String infoHash) {
        if (infoHash == null) return null;
        try {
            JSONObject p = new JSONObject();
            p.put("ac", "get_user_task");
            p.put("info_hash", infoHash);
            p.put("app", "android");
            p.put("app_ver", APP_VER);
            JSONObject inner = apiPostRsa(OFFLINE_API, p, 10000);
            if (inner == null) return null;
            String fid = inner.optString("file_id", "").trim();
            return fid.isEmpty() ? null : fid;
        } catch (Exception e) {
            return null;
        }
    }

    private static String waitFileId(String infoHash, long timeoutMs) {
        long end = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < end) {
            String fid = queryFileId(infoHash);
            if (fid != null) return fid;
            sleep(1500);
        }
        return null;
    }

    private static JSONObject submitMagnet(String magnet) {
        try {
            JSONObject p = new JSONObject();
            p.put("ac", "add_task_url");
            p.put("url", magnet);
            p.put("savepath_id", "0");
            p.put("app", "android");
            p.put("app_ver", APP_VER);
            return apiPostRsa(OFFLINE_API, p, 12000);
        } catch (Exception e) {
            return null;
        }
    }

    /** 列目录内视频，返回 [name, pickcode, sha1] 三元组。 */
    private static List<String[]> fetchFolderVideos(String fid) {
        List<String[]> out = new ArrayList<>();
        if (fid == null || fid.isEmpty()) return out;
        try {
            String url = FILES_API + "?cid=" + URLEncoder.encode(fid, "UTF-8") + "&limit=1000&offset=0&show_dir=1";
            String resp = http("GET", url, null, null);
            if (resp == null) return out;
            JSONObject js = new JSONObject(resp);
            Object dataO = js.opt("data");
            JSONArray arr;
            if (dataO instanceof JSONArray) arr = (JSONArray) dataO;
            else if (dataO instanceof JSONObject) arr = ((JSONObject) dataO).optJSONArray("list");
            else arr = js.optJSONArray("list");
            if (arr == null) return out;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject it = arr.getJSONObject(i);
                String pc = it.optString("pc", it.optString("pickcode", ""));
                String nm = it.optString("n", it.optString("name", ""));
                String sha = it.optString("sha", it.optString("sha1", ""));
                if (pc.isEmpty() || !isVideo(nm)) continue;
                out.add(new String[]{nm, pc, sha});
            }
        } catch (Exception ignore) {
        }
        return out;
    }

    private static List<String[]> searchVideos(String kw) {
        List<String[]> out = new ArrayList<>();
        if (kw == null || kw.isEmpty()) return out;
        try {
            String url = SEARCH_API + "?keyword=" + URLEncoder.encode(kw, "UTF-8") + "&limit=50";
            String resp = http("GET", url, null, null);
            if (resp == null) return out;
            JSONObject js = new JSONObject(resp);
            Object d = js.opt("data");
            JSONArray arr = (d instanceof JSONArray) ? (JSONArray) d : js.optJSONArray("list");
            if (arr == null) return out;
            for (int i = 0; i < arr.length(); i++) {
                JSONObject it = arr.getJSONObject(i);
                String pc = it.optString("pc", it.optString("pickcode", ""));
                String nm = it.optString("n", it.optString("name", ""));
                if (pc.isEmpty() || !isVideo(nm)) continue;
                out.add(new String[]{nm, pc});
            }
        } catch (Exception ignore) {
        }
        return out;
    }

    private static boolean isVideo(String name) {
        if (name == null) return false;
        String n = name.toLowerCase();
        for (String e : VIDEO_EXT) if (n.endsWith(e)) return true;
        return false;
    }

    private static List<String[]> dedup(List<String[]> files) {
        List<String[]> out = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (String[] f : files) if (seen.add(f[1])) out.add(f);
        return out;
    }

    /**
     * 磁力离线并列出所有视频，返回 [集名, pickcode] 列表；失败返回空列表。
     * 路径：查旧任务 file_id（零配额）→ 提交离线 → 轮询专属目录 → 搜索兜底。
     */
    public static List<String[]> offlineAll(String magnet) {
        List<String[]> empty = new ArrayList<>();
        if (cookie.isEmpty()) loadCookie();
        if (cookie.isEmpty()) return empty;
        String ih = btihOf(magnet);
        if (ih == null) return empty;
        // 1) 旧磁力：已在网盘
        String fid = queryFileId(ih);
        if (fid != null) {
            List<String[]> vids = fetchFolderVideos(fid);
            if (!vids.isEmpty()) return filterJunk(vids);
        }
        // 2) 新磁力：提交并轮询专属目录
        submitMagnet(magnet);
        fid = waitFileId(ih, 60000);
        if (fid != null) {
            long end = System.currentTimeMillis() + 15000;
            while (System.currentTimeMillis() < end) {
                List<String[]> vids = fetchFolderVideos(fid);
                if (!vids.isEmpty()) return filterJunk(vids);
                sleep(2000);
            }
        }
        // 3) 兜底：全库模糊搜索
        return dedup(searchVideos(ih));
    }

    private static List<String[]> filterJunk(List<String[]> vids) {
        List<String[]> kept = JunkFilter.filter(vids); // 外置 names/tokens/sha1s + token 边界
        List<String[]> out = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (String[] v : kept) if (seen.add(v[1])) out.add(new String[]{v[0], v[1]}); // 剥回 [name, pickcode]
        return out;
    }

    /** 取原画直链，返回 [url, User-Agent]；失败 url 为空。 */
    public static String[] getDirectUrl(String pickcode) {
        if (cookie.isEmpty()) loadCookie();
        if (cookie.isEmpty() || pickcode == null || pickcode.isEmpty()) return new String[]{"", UA};
        try {
            long uid = 0;
            Matcher m = Pattern.compile("UID=([0-9]+)").matcher(cookie);
            if (m.find()) uid = Long.parseLong(m.group(1));
            JSONObject p = new JSONObject();
            p.put("pickcode", pickcode);
            p.put("user_id", uid);
            JSONObject inner = apiPostRsa(DOWNURL_API, p, 20000);
            if (inner == null) return new String[]{"", UA};
            JSONObject node = inner.optJSONObject(pickcode);
            if (node == null) {
                java.util.Iterator<String> it = inner.keys();
                while (it.hasNext()) {
                    JSONObject v = inner.optJSONObject(it.next());
                    if (v != null && v.has("url")) { node = v; break; }
                }
            }
            if (node == null) return new String[]{"", UA};
            Object uo = node.opt("url");
            String url = "";
            if (uo instanceof JSONObject) url = ((JSONObject) uo).optString("url", "").trim();
            else if (uo instanceof String) url = ((String) uo).trim();
            return new String[]{url, UA};
        } catch (Exception e) {
            return new String[]{"", UA};
        }
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignore) {}
    }
}
