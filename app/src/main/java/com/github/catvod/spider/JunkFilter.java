package com.github.catvod.spider;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * 外置广告黑名单过滤（P115 / PikPak 共用同一份 json，热加载）。
 * 严格复刻 p115.py / pikpak.py 的 _is_junk_video 语义：
 *   - 外置 names    : 文件名全等（小写）命中
 *   - 外置 sha1s    : 内容指纹（大写）命中
 *   - 内置 CJK 词   : 子串匹配（广告/推广/宣傳/宣传/勿动/请先看/必看）
 *   - 拉丁词        : token 边界整词匹配（子串会误伤 Mad.Max/Bad.Boys/Broadway）
 * 外置 tokens 字段同样按 token 边界整词纳入。
 */
public final class JunkFilter {

    private static final String BL_PATH = "/storage/emulated/0/tmp/blacklist/junk_blacklist.json";
    private static final Pattern SPLIT = Pattern.compile("[^a-z0-9]+");
    private static final Set<String> LATIN = new HashSet<>(Arrays.asList(
            "ad", "ads", "advert", "advertisement", "sample", "preview", "trailer",
            "promo", "teaser", "logo", "banner", "spam", "youtube"));
    private static final String[] CJK = {"广告", "推广", "宣傳", "宣传", "勿动", "请先看", "必看"};

    private static long lastMtime = -1;
    private static Set<String> names = Collections.emptySet();
    private static Set<String> tokens = Collections.emptySet();
    private static Set<String> sha1s = Collections.emptySet();

    private JunkFilter() {}

    private static synchronized void reload() {
        File f = new File(BL_PATH);
        long m = f.exists() ? f.lastModified() : -1;
        if (m == lastMtime) return;
        lastMtime = m;
        try {
            InputStream in = new FileInputStream(f);
            BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line);
            br.close();
            JSONObject d = new JSONObject(sb.toString());
            names = lowerSet(d.optJSONArray("names"));
            tokens = lowerSet(d.optJSONArray("tokens"));
            sha1s = upperSet(d.optJSONArray("sha1s"));
        } catch (Exception e) {
            names = tokens = sha1s = Collections.emptySet();
        }
    }

    private static Set<String> lowerSet(JSONArray a) {
        Set<String> s = new HashSet<>();
        if (a != null) for (int i = 0; i < a.length(); i++) {
            String v = a.optString(i, "");
            if (!v.isEmpty()) s.add(v.toLowerCase());
        }
        return s;
    }

    private static Set<String> upperSet(JSONArray a) {
        Set<String> s = new HashSet<>();
        if (a != null) for (int i = 0; i < a.length(); i++) {
            String v = a.optString(i, "");
            if (!v.isEmpty()) s.add(v.toUpperCase());
        }
        return s;
    }

    /** 广告判定：外置 names/sha1s + 内置 CJK 子串 + 拉丁 token 边界。 */
    public static boolean isJunk(String name, String sha1) {
        reload();
        String nm = (name == null ? "" : name).toLowerCase();
        if (names.contains(nm)) return true;
        if (sha1 != null && !sha1.isEmpty() && sha1s.contains(sha1.toUpperCase())) return true;
        for (String k : CJK) if (nm.contains(k)) return true;
        for (String t : SPLIT.split(nm)) {
            if (t.isEmpty()) continue;
            if (LATIN.contains(t) || tokens.contains(t)) return true;
        }
        return false;
    }

    public static boolean isJunk(String name) {
        return isJunk(name, null);
    }

    /** 过滤列表；全部命中时退回原列表（单文件磁力保底）。list 元素 [name, id, ...]。 */
    public static List<String[]> filter(List<String[]> vids) {
        if (vids == null || vids.isEmpty()) return vids;
        List<String[]> kept = new ArrayList<>();
        for (String[] v : vids) {
            String sha = v.length > 2 ? v[2] : null;
            if (!isJunk(v[0], sha)) kept.add(v);
        }
        return kept.isEmpty() ? vids : kept;
    }
}