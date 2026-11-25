package com.github.catvod.spider;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PikPak 网盘 SDK（纯 Java 移植自 Operit/py/pikpak.py）。
 * 凭证：/storage/emulated/0/tmp/auth/pikpak_login.json
 *   {access_token,refresh_token,sub,client_id,device_id,expires_at}
 */
public final class PikPak {

    private static final String LOGIN_JSON = "/storage/emulated/0/tmp/auth/pikpak_login.json";
    private static final String USER_HOST = "https://user.mypikpak.com";
    private static final String API_HOST = "https://api-drive.mypikpak.com";
    private static final String CAPTCHA_INIT_API = USER_HOST + "/v1/shield/captcha/init";
    private static final String TOKEN_API = USER_HOST + "/v1/auth/token";
    private static final String APP_CLIENT_ID = "YNxT9w7GMdWvEOKa";
    private static final String APP_CLIENT_SECRET = "dbw2OtmVEeuUvIptb1Coyg";
    private static final String WEB_CLIENT_ID = "YUMx5nI8ZU8Ap8pm";
    private static final String CLIENT_VERSION = "1.47.1";
    private static final String PACKAGE_NAME = "com.pikcloud.pikpak";
    private static final String SDK_VERSION = "2.0.4.204000";
    private static final String WEB_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";
    private static final String[] VIDEO_EXT = {".mp4", ".mkv", ".avi", ".ts", ".mov", ".flv", ".wmv", ".rmvb", ".iso"};

    // captcha_sign app 通道盐链（从官方 APK 剥出）
    private static final String[] APP_SALTS = {
            "Gez0T9ijiI9WCeTsKSg3SMlx", "zQdbalsolyb1R/", "ftOjr52zt51JD68C3s",
            "yeOBMH0JkbQdEFNNwQ0RI9T3wU/v", "BRJrQZiTQ65WtMvwO", "je8fqxKPdQVJiy1DM6Bc9Nb1",
            "niV", "9hFCW2R1", "sHKHpe2i96", "p7c5E6AcXQ/IJUuAEC9W6", "",
            "aRv9hjc9P+Pbn+u3krN6", "BzStcgE8qVdqjEH16l4", "SqgeZvL5j9zoHP95xWHt",
            "zVof5yaJkPe3VFpadPof",
    };
    // web 通道盐链（mypikpak.com bundle，实测 200）
    private static final String[] WEB_SALTS = {
            "fyZ4+p77W1U4zcWBUwefAIFhFxvADWtT1wzolCxhg9q7etmGUjXr",
            "uSUX02HYJ1IkyLdhINEFcCf7l2",
            "iWt97bqD/qvjIaPXB2Ja5rsBWtQtBZZmaHH2rMR41",
            "3binT1s/5a1pu3fGsN",
            "8YCCU+AIr7pg+yd7CkQEY16lDMwi8Rh4WNp5",
            "DYS3StqnAEKdGddRP8CJrxUSFh",
            "crquW+4",
            "ryKqvW9B9hly+JAymXCIfag5Z",
            "Hr08T/NDTX1oSJfHk90c",
            "i",
    };

    private static JSONObject conf;
    private static String deviceId = "";
    private static final Map<String, String[]> ctCache = new HashMap<>(); // action -> [token, expiryMs]

    private PikPak() {}

    // ---------- 凭证 ----------
    private static void loadConf() {
        if (conf != null) return;
        try {
            java.io.File f = new java.io.File(LOGIN_JSON);
            if (!f.exists()) return;
            InputStream in = new java.io.FileInputStream(f);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            in.close();
            conf = new JSONObject(new String(bos.toByteArray(), StandardCharsets.UTF_8));
            deviceId = conf.optString("device_id", "");
        } catch (Exception e) {
        }
    }

    private static boolean ready() {
        loadConf();
        return conf != null && !conf.optString("access_token", "").isEmpty() && !deviceId.isEmpty();
    }

    // ---------- 哈希 ----------
    private static String md5(String s) {
        try {
            byte[] d = MessageDigest.getInstance("MD5").digest(s.getBytes(StandardCharsets.UTF_8));
            return hex(d);
        } catch (Exception e) {
            return "";
        }
    }

    private static String sha1(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-1").digest(s.getBytes(StandardCharsets.UTF_8));
            return hex(d);
        } catch (Exception e) {
            return "";
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    private static String deviceSign(String did) {
        String s1 = sha1(did + PACKAGE_NAME + "1appkey");
        return "div101." + did + md5(s1);
    }

    private static String appUA(String did, String uid) {
        String[] parts = {
                "ANDROID-" + PACKAGE_NAME + "/" + CLIENT_VERSION,
                "protocolVersion/200", "accesstype/", "clientid/" + APP_CLIENT_ID,
                "clientversion/" + CLIENT_VERSION, "action_type/", "networktype/WIFI",
                "sessionid/", "deviceid/" + did, "providername/NONE",
                "devicesign/" + deviceSign(did), "refresh_token/",
                "sdkversion/" + SDK_VERSION, "datetime/" + System.currentTimeMillis(),
                "usrno/" + (uid == null ? "" : uid), "appname/" + PACKAGE_NAME,
                "session_origin/", "grant_type/", "appid/", "clientip/",
                "devicename/Xiaomi_M2004j7ac", "osversion/13", "platformversion/10",
                "accessmode/", "devicemodel/M2004J7AC",
        };
        return String.join(" ", parts);
    }

    private static String captchaSign(String did, String ts, boolean web) {
        String cid = web ? WEB_CLIENT_ID : APP_CLIENT_ID;
        String ver = web ? "undefined" : CLIENT_VERSION;
        String pkg = web ? "drive.mypikpak.com" : PACKAGE_NAME;
        String[] salts = web ? WEB_SALTS : APP_SALTS;
        String sign = cid + ver + pkg + did + ts;
        for (String salt : salts) sign = md5(sign + salt);
        return "1." + sign;
    }

    // ---------- HTTP ----------
    private static class Resp {
        String body;
        int code;
        Resp(String body, int code) { this.body = body; this.code = code; }
    }

    private static Resp http(String method, String url, String body, Map<String, String> headers) {
        HttpURLConnection conn = null;
        try {
            URL u = new URL(url);
            conn = (HttpURLConnection) u.openConnection();
            conn.setRequestMethod(method);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(20000);
            conn.setInstanceFollowRedirects(true);
            if (headers != null) for (Map.Entry<String, String> e : headers.entrySet())
                conn.setRequestProperty(e.getKey(), e.getValue());
            if (body != null) {
                conn.setDoOutput(true);
                OutputStream os = conn.getOutputStream();
                os.write(body.getBytes(StandardCharsets.UTF_8));
                os.flush();
                os.close();
            }
            int code = conn.getResponseCode();
            InputStream in = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            if (in == null) return new Resp(null, code);
            BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            br.close();
            return new Resp(sb.toString(), code);
        } catch (Exception e) {
            return new Resp(null, -1);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static Map<String, String> headers(boolean withToken, String captchaToken) {
        Map<String, String> h = new HashMap<>();
        h.put("User-Agent", appUA(deviceId, conf.optString("sub", "")));
        h.put("Content-Type", "application/json; charset=utf-8");
        h.put("X-Device-Id", deviceId);
        if (withToken) h.put("Authorization", "Bearer " + conf.optString("access_token", ""));
        if (captchaToken != null && !captchaToken.isEmpty()) h.put("X-Captcha-Token", captchaToken);
        return h;
    }

    /** 由 method+url 推导 captcha action（GET 单文件路径归一化为 /drive/v1/files）。 */
    private static String ctKey(String method, String url) {
        try {
            String path = new URL(url).getPath();
            if ("GET".equals(method)) path = path.replaceFirst("^(/drive/v1/files)/[^/]+$", "$1");
            return method + ":" + path;
        } catch (Exception e) {
            return method + ":" + url;
        }
    }

    private static String captchaToken(String action, boolean force) {
        if (!ready()) return null;
        if (!force) {
            String[] hit = ctCache.get(action);
            if (hit != null && hit[1] != null && Long.parseLong(hit[1]) > System.currentTimeMillis())
                return hit[0];
        }
        try {
            boolean web = WEB_CLIENT_ID.equals(conf.optString("client_id", ""));
            String ts = String.valueOf(System.currentTimeMillis());
            String cid = web ? WEB_CLIENT_ID : APP_CLIENT_ID;
            String ver = web ? "undefined" : CLIENT_VERSION;
            String pkg = web ? "drive.mypikpak.com" : PACKAGE_NAME;
            JSONObject meta = new JSONObject();
            meta.put("captcha_sign", captchaSign(deviceId, ts, web));
            meta.put("client_version", ver);
            meta.put("package_name", pkg);
            meta.put("user_id", conf.optString("sub", ""));
            meta.put("timestamp", ts);
            JSONObject body = new JSONObject();
            body.put("action", action);
            body.put("device_id", deviceId);
            body.put("client_id", cid);
            body.put("meta", meta);
            Resp r = http("POST", CAPTCHA_INIT_API, body.toString(), headers(false, null));
            if (r.body == null) return null;
            String ct = new JSONObject(r.body).optString("captcha_token", "");
            if (!ct.isEmpty()) ctCache.put(action, new String[]{ct, String.valueOf(System.currentTimeMillis() + 540000)});
            return ct.isEmpty() ? null : ct;
        } catch (Exception e) {
            return null;
        }
    }

    /** drive API 请求：自动挂 captcha_token；401 刷新 token，code=9 换 captcha 重试一次。 */
    private static JSONObject api(String method, String url, String body) {
        return api(method, url, body, false, false);
    }

    private static JSONObject api(String method, String url, String body, boolean retried, boolean ctRefreshed) {
        if (!ready()) return null;
        String ct = null;
        if (url.startsWith(API_HOST)) ct = captchaToken(ctKey(method, url), ctRefreshed);
        Resp r = http(method, url, body, headers(true, ct));
        if (r.body == null) return null;
        JSONObject js;
        try { js = new JSONObject(r.body); } catch (Exception e) { return null; }
        int ec = js.optInt("error_code", 0);
        if (ec == 16 && !retried) {
            if (refresh()) return api(method, url, body, true, ctRefreshed);
        } else if (ec == 9 && !ctRefreshed) {
            ctCache.remove(ctKey(method, url));
            return api(method, url, body, retried, true);
        }
        return js;
    }

    private static boolean refresh() {
        if (!ready()) return false;
        try {
            JSONObject b = new JSONObject();
            b.put("client_id", conf.optString("client_id", APP_CLIENT_ID));
            b.put("client_secret", APP_CLIENT_SECRET);
            b.put("refresh_token", conf.optString("refresh_token", ""));
            b.put("grant_type", "refresh_token");
            Resp r = http("POST", TOKEN_API, b.toString(), headers(false, null));
            if (r.body == null) return false;
            JSONObject tok = new JSONObject(r.body);
            String at = tok.optString("access_token", "");
            if (at.isEmpty()) return false;
            conf.put("access_token", at);
            conf.put("refresh_token", tok.optString("refresh_token", conf.optString("refresh_token", "")));
            conf.put("sub", tok.optString("sub", conf.optString("sub", "")));
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static String btihOf(String magnet) {
        if (magnet == null) return null;
        Matcher m = Pattern.compile("btih:([0-9a-fA-F]{40})").matcher(magnet);
        return m.find() ? m.group(1).toLowerCase() : null;
    }

    // ---------- 离线 ----------
    /** 提交离线，返回 [file_id, phase]；失败 null。 */
    private static String[] submit(String magnet, String name) {
        try {
            JSONObject b = new JSONObject();
            b.put("kind", "drive#file");
            if (name != null && !name.isEmpty()) b.put("name", name);
            b.put("upload_type", "UPLOAD_TYPE_URL");
            JSONObject url = new JSONObject();
            url.put("url", magnet);
            b.put("url", url);
            b.put("folder_type", "DOWNLOAD");
            JSONObject js = api("POST", API_HOST + "/drive/v1/files", b.toString());
            if (js == null) return null;
            JSONObject task = js.optJSONObject("task");
            if (task == null) task = new JSONObject();
            String fid = task.optString("file_id", js.optJSONObject("file") == null ? "" : js.optJSONObject("file").optString("id", ""));
            String phase = task.optString("phase", "");
            String tid = task.optString("id", "");
            if (fid.isEmpty() && !tid.isEmpty()) {
                String[] r = waitTaskFileId(tid);
                if (r != null) return r;
            }
            return new String[]{fid.isEmpty() ? null : fid, phase};
        } catch (Exception e) {
            return null;
        }
    }

    private static String[] waitTaskFileId(String taskId) {
        long deadline = System.currentTimeMillis() + 20000;
        double iv = 300;
        String fid = null;
        while (System.currentTimeMillis() < deadline) {
            JSONObject js = api("GET", API_HOST + "/drive/v1/tasks/" + taskId + "?type=offline", null);
            if (js != null) fid = js.optString("file_id", "");
            if (fid != null && !fid.isEmpty()) break;
            sleep((long) iv);
            iv = Math.min(iv + 300, 1200);
        }
        if (fid == null || fid.isEmpty()) return null;
        JSONObject det = api("GET", API_HOST + "/drive/v1/files/" + fid + "?thumbnail_size=SIZE_SMALL", null);
        return new String[]{fid, det == null ? "" : det.optString("phase", "")};
    }

    private static boolean waitComplete(String fid, long timeoutMs) {
        long deadline = System.currentTimeMillis() + timeoutMs;
        double iv = 300;
        while (System.currentTimeMillis() < deadline) {
            JSONObject js = api("GET", API_HOST + "/drive/v1/files/" + fid + "?thumbnail_size=SIZE_SMALL", null);
            if (js != null && "PHASE_TYPE_COMPLETE".equals(js.optString("phase", ""))) return true;
            sleep((long) iv);
            iv = Math.min(iv + 300, 1200);
        }
        return false;
    }

    private static JSONArray listDir(String parentId) {
        try {
            JSONObject filters = new JSONObject();
            JSONObject trashed = new JSONObject(); trashed.put("eq", false); filters.put("trashed", trashed);
            JSONObject phase = new JSONObject(); phase.put("eq", "PHASE_TYPE_COMPLETE"); filters.put("phase", phase);
            String url = API_HOST + "/drive/v1/files?parent_id=" + enc(parentId) + "&limit=100&with_audit=true&filters=" + enc(filters.toString());
            JSONObject js = api("GET", url, null);
            return js == null ? new JSONArray() : js.optJSONArray("files");
        } catch (Exception e) {
            return new JSONArray();
        }
    }

    /** 收集目录（含两层子目录）内视频，返回 [name, id] 列表。 */
    private static List<String[]> collectVideos(String fid, int depth) {
        List<String[]> out = new ArrayList<>();
        JSONArray arr = listDir(fid);
        for (int i = 0; i < arr.length(); i++) {
            JSONObject it = arr.optJSONObject(i);
            if (it == null) continue;
            String nm = it.optString("name", "");
            String id = it.optString("id", "");
            if ("drive#folder".equals(it.optString("kind", ""))) {
                if (depth < 2) out.addAll(collectVideos(id, depth + 1));
                continue;
            }
            if (!isVideo(nm) || id.isEmpty()) continue;
            out.add(new String[]{nm, id});
        }
        return JunkFilter.filter(out); // 外置 names/tokens/sha1s + token 边界（与 p115 共用）
    }

    private static boolean isVideo(String name) {
        if (name == null) return false;
        String n = name.toLowerCase();
        for (String e : VIDEO_EXT) if (n.endsWith(e)) return true;
        return false;
    }

    /** 从视频列表挑一个：优先体积/名称命中，否则取第一个。 */
    private static String pickVideo(String fid, JSONArray files) {
        // 单文件种子：fid 本身即视频
        JSONObject det = api("GET", API_HOST + "/drive/v1/files/" + fid + "?thumbnail_size=SIZE_SMALL", null);
        if (det != null && !"drive#folder".equals(det.optString("kind", "")) && isVideo(det.optString("name", "")))
            return fid;
        List<String[]> vids = collectVideos(fid, 0);
        if (vids.isEmpty()) return null;
        return vids.get(0)[1];
    }

    /**
     * 磁力离线并返回视频 file_id；失败 null。
     */
    public static String offline(String magnet) {
        if (!ready() || btihOf(magnet) == null) return null;
        long end = System.currentTimeMillis() + 45000;
        String[] r = submit(magnet, null);
        if (r == null || r[0] == null) return null;
        String fid = r[0];
        if (!"PHASE_TYPE_COMPLETE".equals(r[1]) && !waitComplete(fid, Math.max(1000, end - System.currentTimeMillis())))
            return null;
        // 子文件可能滞后，重试列目录
        String picked = null;
        long t0 = System.currentTimeMillis();
        double iv = 500;
        while (System.currentTimeMillis() - t0 < Math.max(1000, end - System.currentTimeMillis())) {
            picked = pickVideo(fid, new JSONArray());
            if (picked != null) break;
            sleep((long) iv);
            iv = Math.min(iv + 250, 1500);
        }
        return picked;
    }

    /** 点集播放: 离线并按 targetName 精确取一个文件 -> 直链; 返回 [url, UA], 失败 url 空。 */
    public static String[] offlineOne(String magnet, String targetName) {
        String[] fail = {"", WEB_UA};
        if (!ready() || btihOf(magnet) == null) return fail;
        long end = System.currentTimeMillis() + 45000;
        String[] r = submit(magnet, null);
        if (r == null || r[0] == null) return fail;
        String fid = r[0];
        if (!"PHASE_TYPE_COMPLETE".equals(r[1]) && !waitComplete(fid, Math.max(1000, end - System.currentTimeMillis())))
            return fail;
        String picked = null;
        long t0 = System.currentTimeMillis();
        double iv = 500;
        while (System.currentTimeMillis() - t0 < Math.max(1000, end - System.currentTimeMillis())) {
            List<String[]> vids = collectVideos(fid, 0);
            if (targetName != null && !targetName.isEmpty()) {
                String base = targetName.substring(targetName.lastIndexOf('/') + 1).toLowerCase();
                for (String[] v : vids) if (v[0].toLowerCase().equals(base)) { picked = v[1]; break; }
            }
            if (picked == null && !vids.isEmpty()) picked = vids.get(0)[1];
            if (picked == null) picked = pickVideo(fid, new JSONArray());
            if (picked != null) break;
            sleep((long) iv);
            iv = Math.min(iv + 250, 1500);
        }
        if (picked == null) return fail;
        return getDirectUrl(picked);
    }

    /** 取播放直链，返回 [url, User-Agent]；失败 url 为空。 */
    public static String[] getDirectUrl(String fileId) {
        if (!ready() || fileId == null || fileId.isEmpty()) return new String[]{"", WEB_UA};
        JSONObject js = api("GET", API_HOST + "/drive/v1/files/" + fileId + "?thumbnail_size=SIZE_SMALL", null);
        if (js == null) return new String[]{"", WEB_UA};
        JSONArray medias = js.optJSONArray("medias");
        if (medias != null) for (int i = 0; i < medias.length(); i++) {
            JSONObject m = medias.optJSONObject(i);
            if (m == null) continue;
            JSONObject link = m.optJSONObject("link");
            String u = link == null ? "" : link.optString("url", "");
            if (!u.isEmpty()) return new String[]{u, WEB_UA};
        }
        String u = js.optString("web_content_link", "");
        return new String[]{u, WEB_UA};
    }

    private static String enc(String s) {
        try { return URLEncoder.encode(s, "UTF-8"); } catch (Exception e) { return s; }
    }

    private static void sleep(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignore) {}
    }
}