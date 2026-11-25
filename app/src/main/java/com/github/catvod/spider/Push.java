package com.github.catvod.spider;

import android.text.TextUtils;

import com.github.catvod.bean.Sub;
import com.github.catvod.bean.Vod;
import com.github.catvod.crawler.Spider;
import com.github.catvod.utils.Image;
import com.github.catvod.utils.Path;
import com.github.catvod.utils.Response;
import com.github.catvod.utils.VodUtil;

import java.io.File;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class Push extends Spider {

    private static final Pattern THUNDER = Pattern.compile("(magnet|thunder|ed2k):.*");
    private static final String FLAG_115 = "115";
    private static final String FLAG_PIKPAK = "PikPak";
    private static final String FLAG_DEFAULT = "默认";
    private static final String PULL = "__pull__";

    @Override
    public String detailContent(List<String> ids) {
        List<Vod> items = new ArrayList<>();
        for (String id : ids) {
            if (id != null && id.toLowerCase().startsWith("magnet:")) items.add(magnetVod(id));
            else items.add(vod(id));
        }
        return Response.create().vods(items).string();
    }

    /** 磁力铺线(详情阶段零离线): 115 旧磁力只读列举铺多集, 否则扩展线单集占位;
     *  PikPak 扩展线单集占位; 原有默认线交内核 DHT 永远保留。点某集才在 playerContent 激活对应盘离线。 */
    private Vod magnetVod(String magnet) {
        Vod vod = Vod.create().id(magnet).name(magnetName(magnet)).pic(Image.PUSH).typeName("FongMi");
        String qm = enc(magnet);
        String disp = magnetName(magnet);
        List<String> froms = new ArrayList<>();
        List<String> urls = new ArrayList<>();

        // 扩展线 115: 旧磁力只读列举铺多集(不提交不离线, 零配额)
        List<String[]> v115 = P115.listVideosReadOnly(magnet);
        if (v115.size() > 1) {
            StringBuilder sb = new StringBuilder();
            for (String[] f : v115) {
                if (sb.length() > 0) sb.append('#');
                sb.append(clean(f[0])).append('$').append(PULL).append(FLAG_115)
                  .append('@').append(qm).append('@').append(enc(f[0]));
            }
            froms.add(FLAG_115); urls.add(sb.toString());
        } else {
            froms.add(FLAG_115);
            urls.add(disp + '$' + PULL + FLAG_115 + '@' + qm + '@');
        }

        // 扩展线 PikPak: 单集占位(点集才离线)
        froms.add(FLAG_PIKPAK);
        urls.add(disp + '$' + PULL + FLAG_PIKPAK + '@' + qm + '@');

        // 原有线: 交内核 DHT 直播(id 即原磁力), 永远保留
        froms.add(FLAG_DEFAULT);
        urls.add(disp + '$' + magnet);

        return vod.playFrom(TextUtils.join("$$$", froms)).playUrl(TextUtils.join("$$$", urls));
    }

    @Override
    public String playerContent(String flag, String id, List<String> vipFlags) {
        if (id != null && id.startsWith(PULL)) return pull(id);
        // 旧扩展兼容(老收藏 id 直接是 pickcode/fileId)
        if (FLAG_115.equals(flag)) {
            String[] r = P115.getDirectUrl(id);
            return Response.create().url(r[0]).header(singleHeader("User-Agent", r[1])).string();
        }
        if (FLAG_PIKPAK.equals(flag)) {
            String[] r = PikPak.getDirectUrl(id);
            return Response.create().url(r[0]).header(singleHeader("User-Agent", r[1])).string();
        }
        if (id != null && id.contains("://") && id.contains("***")) id = id.replace("***", "#");
        Response result = Response.create().url(id);
        switch (flag) {
            case "直連" -> result.subs(getSubs(id));
            case "解析" -> result.parse().jx();
            case "嗅探" -> result.parse();
        }
        return result.string();
    }

    /** 点集: 激活对应盘离线按 targetName 精确取该文件 -> 直链; 失败兜底原磁力交内核。 */
    private String pull(String id) {
        String[] p = id.substring(PULL.length()).split("@", -1);
        String flag = p.length > 0 ? p[0] : "";
        String magnet = p.length > 1 ? dec(p[1]) : "";
        String target = p.length > 2 ? dec(p[2]) : "";
        String[] r = null;
        if (FLAG_115.equals(flag)) r = P115.offlineOne(magnet, target);
        else if (FLAG_PIKPAK.equals(flag)) r = PikPak.offlineOne(magnet, target);
        if (r != null && r[0] != null && !r[0].isEmpty())
            return Response.create().url(r[0]).header(singleHeader("User-Agent", r[1])).string();
        return Response.create().url(magnet).string();
    }

    private static String enc(String s) {
        try { return URLEncoder.encode(s == null ? "" : s, "UTF-8"); }
        catch (Exception e) { return s == null ? "" : s; }
    }

    private static String dec(String s) {
        try { return URLDecoder.decode(s == null ? "" : s, "UTF-8"); }
        catch (Exception e) { return s == null ? "" : s; }
    }

    /** 磁力显示名: 优先 dn= 参数(URL 解码), 无 dn 退回 btih 前 8 位(对齐 py)。 */
    private static String magnetName(String magnet) {
        if (magnet == null) return "";
        String name = "";
        int i = magnet.indexOf("dn=");
        if (i >= 0) {
            int s = i + 3;
            int e = magnet.indexOf('&', s);
            name = dec(e >= 0 ? magnet.substring(s, e) : magnet.substring(s));
        }
        if (name.isEmpty()) {
            int b = magnet.indexOf("btih:");
            if (b >= 0) {
                String h = magnet.substring(b + 5);
                int e = h.indexOf('&');
                if (e >= 0) h = h.substring(0, e);
                name = "Push " + (h.length() > 8 ? h.substring(0, 8) : h);
            }
        }
        return clean(name);
    }

    private static String clean(String s) {
        return s == null ? "" : s.replace('#', ' ').replace('$', ' ');
    }

    private java.util.Map<String, String> singleHeader(String k, String v) {
        java.util.Map<String, String> m = new java.util.HashMap<>();
        m.put(k, v);
        return m;
    }

    private Vod vod(String url) {
        // ==== CatVodSpider 原版 Push 逻辑, 一字不动 ====
        Vod vod = Vod.create().id(url).name(url.startsWith("file://") ? new File(url).getName() : "").pic(Image.PUSH).typeName("FongMi");
        if (url.contains("://") && url.contains("#")) url = url.replace("#", "***");
        if (isThunder(url)) {
            return vod.playUrl(url).playFrom("迅雷");
        } else if (url.contains("youtube.com")) {
            return vod.playUrl(url).playFrom("YouTube");
        } else if (url.contains("$")) {
            return vod.playFrom("直連").playUrl(TextUtils.join("#", url.split("\n")));
        } else {
            return vod.playUrl(TextUtils.join("$$$", Arrays.asList(url, url, url))).playFrom(TextUtils.join("$$$", Arrays.asList("直連", "嗅探", "解析")));
        }
    }

    private boolean isThunder(String url) {
        return THUNDER.matcher(url).find() || isTorrent(url);
    }

    private boolean isTorrent(String url) {
        return !url.startsWith("magnet") && url.split(";")[0].endsWith(".torrent");
    }

    private List<Sub> getSubs(String url) {
        List<Sub> subs = new ArrayList<>();
        if (!url.startsWith("file://")) return subs;
        File parent = new File(url.replace("file://", "")).getParentFile();
        if (parent == null) return subs;
        for (File f : Path.list(parent)) {
            String ext = VodUtil.getExt(f.getName());
            if (!f.isFile() || !VodUtil.isSub(ext)) continue;
            subs.add(Sub.create().name(VodUtil.removeExt(f.getName())).format(ext).url("file://" + f.getAbsolutePath()));
        }
        return subs;
    }
}