package recloudstream

/**
 * Hydrax / Abyss.to ("HY" server) extractor.
 *
 * Ported from AbyssVideoDownloader (github.com/abdlhay/AbyssVideoDownloader).
 * The HY server on Anime47 embeds videos from abysscdn.com / playhydrax.com / zplayer.io.
 * Those pages ship a base64 blob called `datas` containing an AES-CTR encrypted JSON
 * payload that, once decrypted, lists CDN "sources" (resolutions). Actual segment bytes
 * are fetched from `{sub}.{domain}/sora/{size}/{token}` where `token` is itself an
 * AES-CTR encrypted+double-base64 path — there is no normal HLS/mp4 URL to hand to
 * a player directly, so we relay through a fake local URL + [HydraxInterceptor] that
 * translates player Range requests into the segment-token protocol on the fly.
 */

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.lagradost.cloudstream3.app
import com.lagradost.cloudstream3.utils.ExtractorLink
import com.lagradost.cloudstream3.utils.ExtractorLinkType
import com.lagradost.cloudstream3.utils.Qualities
import com.lagradost.cloudstream3.utils.newExtractorLink
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import okio.Source
import okio.Timeout
import okio.buffer
import java.net.URI
import java.net.URLEncoder
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object HydraxExtractor {

    private val mapper = jacksonObjectMapper()
    private const val FRAGMENT_SIZE = 2097152L // 2 MiB, must match server-side chunking
    const val RELAY_HOST = "hydrax-relay.internal"
    private const val ABYSS_BASE_URL = "https://abysscdn.com"

    private val HY_HOSTS = listOf("abysscdn.com", "playhydrax.com", "zplayer.io", "short.ink")

    fun isHydraxUrl(url: String): Boolean {
        val host = runCatching { URI(url).host }.getOrNull() ?: return false
        return HY_HOSTS.any { host.contains(it, ignoreCase = true) }
    }

    // ===================== crypto helpers (mirrors AbyssVideoDownloader's CryptoHelper) =====================

    private fun md5Hex(bytes: ByteArray): String {
        val digest = java.security.MessageDigest.getInstance("MD5").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    /** getKey() for a Number: each digit char -> its numeric value as a raw byte. */
    private fun keyForNumber(value: Long): String {
        val bytes = value.toString().map { c ->
            if (c.isDigit()) c.digitToInt().toByte() else c.code.toByte()
        }.toByteArray()
        return md5Hex(bytes)
    }

    /** getKey() for a String: plain UTF-8 bytes. */
    private fun keyForString(value: String): String = md5Hex(value.toByteArray(Charsets.UTF_8))

    private fun aesCtrEncryptToIso(data: String, keyHex: String): String {
        val keyBytes = keyHex.toByteArray(Charsets.UTF_8)
        val iv = keyBytes.copyOfRange(0, 16)
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), IvParameterSpec(iv))
        val encrypted = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
        return String(encrypted, Charsets.ISO_8859_1)
    }

    private fun aesCtrDecryptFromIso(cipherIso: String, keyHex: String): String {
        val keyBytes = keyHex.toByteArray(Charsets.UTF_8)
        val iv = keyBytes.copyOfRange(0, 16)
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(keyBytes, "AES"), IvParameterSpec(iv))
        val cipherBytes = ByteArray(cipherIso.length) { cipherIso[it].code.toByte() }
        val decrypted = cipher.doFinal(cipherBytes)
        return String(decrypted, Charsets.UTF_8)
    }

    private fun doubleBase64(input: String): String {
        val first = Base64.getEncoder().encodeToString(input.toByteArray(Charsets.ISO_8859_1)).replace("=", "")
        return Base64.getEncoder().encodeToString(first.toByteArray()).replace("=", "")
    }

    private fun buildSegmentToken(md5Id: Int, resId: Int, size: Long, index: Int): String {
        val path = "/mp4/$md5Id/$resId/$size/$FRAGMENT_SIZE/$index"
        val key = keyForNumber(size)
        return doubleBase64(aesCtrEncryptToIso(path, key))
    }

    // ===================== models =====================

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class Datas(
        val md5_id: Int? = null,
        val media: String? = null,
        val slug: String? = null,
        val user_id: Int? = null
    )

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class SourceEntry(
        val label: String? = null,
        val size: Long? = null,
        val sub: String? = null,
        val res_id: Int? = null
    )

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class Mp4Data(
        val domains: List<String?>? = null,
        val sources: List<SourceEntry?>? = null,
        val slug: String? = null,
        val md5_id: Int? = null
    )

    @JsonIgnoreProperties(ignoreUnknown = true)
    private data class VideoData(val mp4: Mp4Data? = null)

    // ===================== id / metadata extraction =====================

    private fun getVideoId(url: String): String? {
        val host = runCatching { URI(url).host }.getOrNull() ?: return url
        return when {
            host.contains("short.ink") -> url.substringAfterLast("/")
            host.contains("abysscdn.com") || host.contains("playhydrax.com") || host.contains("zplayer.io") ->
                runCatching {
                    URI(url).query?.split("&")
                        ?.map { it.split("=") }
                        ?.firstOrNull { it.getOrNull(0) == "v" }
                        ?.getOrNull(1)
                }.getOrNull()
            else -> url
        }
    }

    private suspend fun fetchMp4Metadata(videoId: String, referer: String): Mp4Data? {
        val embedUrl = "$ABYSS_BASE_URL/?v=$videoId"
        val html = app.get(
            embedUrl,
            headers = mapOf(
                "Referer" to referer,
                "User-Agent" to "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
            ),
            timeout = 15000
        ).text

        val doc = org.jsoup.Jsoup.parse(html)
        val scriptHtml = doc.select("script").map { it.html() }.firstOrNull { it.contains("datas") }
            ?: return null

        val encodedDatas = Regex("""const\s+datas\s*=\s*"([^"]*)"""").find(scriptHtml)
            ?.groupValues?.get(1) ?: return null

        val decodedJson = String(Base64.getDecoder().decode(encodedDatas), Charsets.ISO_8859_1)
        val datas = mapper.readValue(decodedJson, Datas::class.java)
        val encryptedMedia = datas.media ?: return null

        val mediaKey = keyForString("${datas.user_id}:${datas.slug}:${datas.md5_id}")
        val decryptedJson = aesCtrDecryptFromIso(encryptedMedia, mediaKey)
        val video = mapper.readValue(decryptedJson, VideoData::class.java)

        return video.mp4?.copy(slug = datas.slug, md5_id = datas.md5_id)
    }

    // ===================== public API =====================

    /**
     * Resolves a HY (Hydrax/Abyss) stream URL into one or more playable [ExtractorLink]s.
     * The returned links point at a local relay host; pair with [HydraxInterceptor] via
     * MainAPI.getVideoInterceptor for playback to work.
     */
    suspend fun getLinks(
        streamUrl: String,
        providerName: String,
        serverName: String?,
        referer: String
    ): List<ExtractorLink> {
        val videoId = getVideoId(streamUrl) ?: return emptyList()
        val mp4 = fetchMp4Metadata(videoId, referer) ?: return emptyList()
        val md5Id = mp4.md5_id ?: return emptyList()
        // Trước đây chỉ lấy domains?.firstOrNull() và dùng chung 1 domain cho MỌI
        // resolution. Điều đó đúng với đa số tập (chỉ có 1 domain thật sự), nhưng với
        // các tập mà CDN phân nhiều domain cho các resolution khác nhau, source nào
        // không thuộc domain đầu tiên sẽ bị build sai baseUrl -> lỗi phát ngay lập tức
        // dù server HY vẫn ổn trên web. Vì ta không biết chắc source nào ứng với domain
        // nào từ metadata tĩnh, mang theo TOÀN BỘ domain candidates qua relay URL và để
        // HydraxInterceptor tự thử lần lượt khi mở segment đầu tiên thất bại.
        val domainCandidates = mp4.domains?.filterNotNull()?.map { it.trim() }?.filter { it.isNotBlank() }?.distinct()
            ?: return emptyList()
        if (domainCandidates.isEmpty()) return emptyList()
        val sources = mp4.sources?.filterNotNull().orEmpty()
        val displayBaseName = serverName?.takeIf { it.isNotBlank() } ?: "$providerName HY"

        return sources.mapNotNull { source ->
            val sub = source.sub ?: return@mapNotNull null
            val size = source.size ?: return@mapNotNull null
            val resId = source.res_id ?: return@mapNotNull null
            val baseUrls = domainCandidates.map { domain -> "https://$sub.${domain.substringAfter(".")}" }.distinct()
            val relayUrl = buildRelayUrl(baseUrls, md5Id, resId, size)
            val quality = source.label?.filter { it.isDigit() }?.toIntOrNull() ?: Qualities.Unknown.value

            newExtractorLink(
                providerName,
                displayBaseName,
                relayUrl,
                ExtractorLinkType.VIDEO
            ) {
                this.referer = referer
                this.quality = quality
                this.headers = mapOf("Referer" to referer)
            }
        }
    }

    private fun buildRelayUrl(baseUrls: List<String>, md5Id: Int, resId: Int, size: Long): String {
        val encodedBases = baseUrls.joinToString(",") { URLEncoder.encode(it, "UTF-8") }
        return "https://$RELAY_HOST/video.mp4?bases=$encodedBases&md5=$md5Id&res=$resId&size=$size"
    }
}

/**
 * Translates player Range requests against the fake `hydrax-relay.internal` host into
 * Abyss's token-chunked segment protocol, streaming segments lazily (no full-file buffering).
 */
object HydraxInterceptor : Interceptor {

    private const val FRAGMENT_SIZE = 2097152L
    // Connection pool lớn hơn mặc định (5) để giữ kết nối tới CDN sống lâu hơn giữa các
    // segment request liên tiếp và cho prefetch chạy song song, tránh phải bắt tay TLS
    // lại từ đầu mỗi lần — đây là phần đóng góp lớn vào độ trễ "chờ lấy link stream lâu".
    private val client = OkHttpClient.Builder()
        .connectionPool(okhttp3.ConnectionPool(8, 60, java.util.concurrent.TimeUnit.SECONDS))
        .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
        .readTimeout(20, java.util.concurrent.TimeUnit.SECONDS)
        .build()

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (request.url.host != HydraxExtractor.RELAY_HOST) {
            return chain.proceed(request)
        }

        // Lưu ý: OkHttp's HttpUrl.queryParameter() đã tự decode giá trị query param (đúng
        // 1 lần), nên KHÔNG được URLDecoder.decode() thêm lần nữa ở đây kẻo double-decode
        // hỏng URL (ví dụ nếu domain gốc từng chứa ký tự "%"). Mỗi base URL được encode
        // riêng lẻ bằng URLEncoder trước khi join bằng dấu phẩy ở phía buildRelayUrl(), và
        // dấu phẩy nằm trong danger-set nên chắc chắn không xuất hiện bên trong 1 base đã
        // encode — an toàn để split(",") sau khi OkHttp decode xong.
        val baseUrls = request.url.queryParameter("bases")
            ?.split(",")
            ?.filter { it.isNotBlank() }
            // "base" (số ít) giữ lại để tương thích ngược nếu relay URL cũ còn tồn tại đâu đó.
            ?: request.url.queryParameter("base")?.let { listOf(it) }
        val md5Id = request.url.queryParameter("md5")?.toIntOrNull()
        val resId = request.url.queryParameter("res")?.toIntOrNull()
        val size = request.url.queryParameter("size")?.toLongOrNull()

        if (baseUrls.isNullOrEmpty() || md5Id == null || resId == null || size == null) {
            return errorResponse(request, 500, "Missing relay parameters")
        }

        val rangeHeader = request.header("Range")
        val (start, endInclusive) = parseRange(rangeHeader, size)
        if (start > endInclusive || start < 0) {
            return errorResponse(request, 416, "Invalid range")
        }

        val segmentSource = SegmentSource(client, baseUrls, md5Id, resId, size, start, endInclusive)
        val contentLength = endInclusive - start + 1
        val body: ResponseBody = segmentSource.buffer()
            .let { buffered -> object : ResponseBody() {
                override fun contentType() = "video/mp4".toMediaTypeOrNull()
                override fun contentLength() = contentLength
                override fun source() = buffered
            } }

        val builder = Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .header("Accept-Ranges", "bytes")
            .header("Content-Length", contentLength.toString())
            .body(body)

        return if (rangeHeader != null) {
            builder.code(206).message("Partial Content")
                .header("Content-Range", "bytes $start-$endInclusive/$size")
                .build()
        } else {
            builder.code(200).message("OK").build()
        }
    }

    private fun parseRange(header: String?, totalSize: Long): Pair<Long, Long> {
        if (header == null) return 0L to (totalSize - 1)
        val match = Regex("""bytes=(\d+)-(\d*)""").find(header) ?: return 0L to (totalSize - 1)
        val start = match.groupValues[1].toLongOrNull() ?: 0L
        val end = match.groupValues[2].toLongOrNull() ?: (totalSize - 1)
        return start to minOf(end, totalSize - 1)
    }

    private fun errorResponse(request: Request, code: Int, message: String): Response {
        return Response.Builder()
            .request(request)
            .protocol(Protocol.HTTP_1_1)
            .code(code)
            .message(message)
            .body("".toResponseBody(null))
            .build()
    }

    /**
     * Lazily streams Abyss segments as the player consumes bytes.
     *
     * Tối ưu độ trễ "vào player rồi loading lâu mới có hình":
     * 1. STREAMING THẬT SỰ (thay đổi quan trọng nhất): bản gốc gọi resp.body.bytes()
     *    — tải nguyên 2MB segment vào RAM rồi mới trả byte đầu tiên cho player, nên
     *    player phải chờ trọn 2MB tải xong mới bắt đầu decode/hiển thị hình. Bản này
     *    giữ kết nối HTTP đang mở (BufferedSource) và forward dữ liệu cho player ngay
     *    khi network trả về, không đợi tải hết segment — giảm đáng kể thời gian tới
     *    byte đầu tiên, đặc biệt quan trọng cho lần load đầu của mỗi video.
     * 2. OkHttpClient dùng chung có connection pool lớn hơn mặc định — tránh phải bắt
     *    tay TLS lại từ đầu cho mỗi segment request.
     * 3. Prefetch: song song với việc đọc segment hiện tại, một coroutine nền tải
     *    trước segment kế tiếp (vẫn dùng cách tải trọn vào RAM vì không cần độ trễ
     *    thấp ở đây — mục tiêu là có sẵn trước khi cần), để giảm giật khi chuyển
     *    giữa các segment 2MB.
     *
     * Lưu ý: kích thước segment (FRAGMENT_SIZE = 2MB) do server Abyss chunk cố định,
     * không thể xin một kích thước nhỏ hơn cho riêng lần tải đầu — nên độ trễ khi bấm
     * play lần đầu (trước khi vào player, lúc lấy metadata + link) vẫn phụ thuộc tốc
     * độ mạng tới abysscdn.com, không thể giảm thêm ở phía client.
     */
    private class SegmentSource(
        private val client: OkHttpClient,
        private val baseUrls: List<String>,
        private val md5Id: Int,
        private val resId: Int,
        private val totalSize: Long,
        startByte: Long,
        private val endByteInclusive: Long
    ) : Source {

        private var currentPos = startByte
        private val currentBuffer = Buffer()

        // Domain nào trong baseUrls thực sự phục vụ được segment sẽ được chốt lại ở đây
        // sau lần thử thành công đầu tiên, để các segment sau không phải thử lại từ đầu.
        // Nếu domain đã chốt bỗng lỗi giữa chừng (CDN đó sập), quay lại thử toàn bộ danh
        // sách một lần nữa thay vì bó cứng vào 1 domain duy nhất.
        @Volatile
        private var resolvedBaseUrl: String? = baseUrls.singleOrNull()

        // Cache segment đã prefetch để không tải lại khi tới lượt đọc thật.
        private val prefetchCache = java.util.concurrent.ConcurrentHashMap<Int, ByteArray>()
        private val prefetchInFlight = java.util.concurrent.ConcurrentHashMap.newKeySet<Int>()
        private val prefetchExecutor = java.util.concurrent.Executors.newFixedThreadPool(2)

        // Kết nối HTTP đang mở cho segment hiện tại (đọc dần, KHÔNG tải hết vào RAM
        // trước khi trả cho player — xem ghi chú ở đầu class).
        private var openResponse: Response? = null
        private var openSource: okio.BufferedSource? = null
        private var openSegIndex: Int = -1

        override fun read(sink: Buffer, byteCount: Long): Long {
            if (currentPos > endByteInclusive) return -1L

            val segIndex = (currentPos / FRAGMENT_SIZE).toInt()
            val segStart = segIndex.toLong() * FRAGMENT_SIZE

            // Ưu tiên dữ liệu đã prefetch sẵn trong RAM (đã tải xong từ trước) — trường
            // hợp này copy thẳng, không cần mở connection mới.
            if (currentBuffer.exhausted() && openSegIndex != segIndex) {
                prefetchCache.remove(segIndex)?.let { bytes ->
                    val offsetInSeg = (currentPos - segStart).toInt().coerceIn(0, bytes.size)
                    currentBuffer.write(bytes, offsetInSeg, bytes.size - offsetInSeg)
                    schedulePrefetch(segIndex + 1)
                }
            }

            if (!currentBuffer.exhausted()) {
                val remaining = endByteInclusive - currentPos + 1
                val toRead = minOf(byteCount, remaining, currentBuffer.size)
                if (toRead <= 0) return -1L
                val read = currentBuffer.read(sink, toRead)
                if (read > 0) currentPos += read
                return read
            }

            // Chưa có sẵn trong buffer/cache: đọc trực tiếp (streaming) từ kết nối HTTP,
            // mở kết nối mới nếu chưa có hoặc đã chuyển sang segment khác.
            if (openSegIndex != segIndex) {
                closeOpenConnection()
                val opened = openSegmentStream(segIndex) ?: return -1L
                openResponse = opened.first
                openSource = opened.second
                openSegIndex = segIndex

                // Bỏ qua phần đầu segment nếu currentPos không trùng đầu segment
                // (trường hợp resume giữa segment sau khi đã đọc một phần).
                val skipBytes = currentPos - segStart
                if (skipBytes > 0) {
                    openSource?.skip(skipBytes)
                }
            }

            val remaining = endByteInclusive - currentPos + 1
            val wantToRead = minOf(byteCount, remaining, FRAGMENT_SIZE)
            var read = try {
                openSource?.read(sink, wantToRead) ?: -1L
            } catch (e: Exception) {
                -1L
            }

            // read == -1 có 2 khả năng: (a) đã đọc hết đúng segment này (bình thường,
            // segment cuối cùng của file có thể nhỏ hơn FRAGMENT_SIZE), hoặc (b) kết nối
            // bị gián đoạn giữa chừng trước khi đọc đủ dữ liệu mong đợi. Phân biệt bằng
            // cách so sánh currentPos với ranh giới segment: nếu chưa tới ranh giới mà đã
            // -1, thử mở lại kết nối đúng 1 lần trước khi coi là lỗi thật.
            if (read <= 0) {
                val segEndExclusive = minOf(segStart + FRAGMENT_SIZE, endByteInclusive + 1)
                val genuinelyAtSegmentEnd = currentPos >= segEndExclusive
                if (!genuinelyAtSegmentEnd) {
                    closeOpenConnection()
                    val retryOpened = openSegmentStream(segIndex)
                    if (retryOpened != null) {
                        openResponse = retryOpened.first
                        openSource = retryOpened.second
                        openSegIndex = segIndex
                        val skipBytes = currentPos - segStart
                        if (skipBytes > 0) openSource?.skip(skipBytes)
                        read = try {
                            openSource?.read(sink, wantToRead) ?: -1L
                        } catch (e: Exception) {
                            -1L
                        }
                    }
                }
            }

            if (read > 0) {
                currentPos += read
                // Ngay khi bắt đầu đọc segment hiện tại, kích hoạt prefetch cho segment
                // kế tiếp chạy song song trong nền (không dùng chung connection này).
                schedulePrefetch(segIndex + 1)
            } else {
                // Hết segment hiện tại (hoặc lỗi không thể phục hồi) -> đóng connection,
                // lần read() sau sẽ tự mở segment kế tiếp.
                closeOpenConnection()
            }
            return read
        }

        override fun timeout(): Timeout = Timeout.NONE
        override fun close() {
            closeOpenConnection()
            prefetchExecutor.shutdownNow()
        }

        private fun closeOpenConnection() {
            try {
                openResponse?.close()
            } catch (e: Exception) {
                // ignore
            }
            openResponse = null
            openSource = null
            openSegIndex = -1
        }

        /** Mở kết nối HTTP tới segment nhưng KHÔNG đọc hết body — trả về source để đọc dần.
         *
         * Thử domain đã chốt (resolvedBaseUrl) trước nếu có. Nếu chưa chốt hoặc domain đó
         * lỗi, thử lần lượt toàn bộ baseUrls — CDN có thể phân domain khác nhau theo
         * resolution, nên không thể biết trước domain nào đúng chỉ từ metadata tĩnh.
         * Domain đầu tiên trả về thành công sẽ được chốt lại cho các lần gọi sau.
         */
        private fun openSegmentStream(index: Int): Pair<Response, okio.BufferedSource>? {
            val ordered = resolvedBaseUrl?.let { resolved ->
                listOf(resolved) + baseUrls.filter { it != resolved }
            } ?: baseUrls

            for (candidate in ordered) {
                val path = "/mp4/$md5Id/$resId/$totalSize/$FRAGMENT_SIZE/$index"
                val token = tokenFor(path)
                val segUrl = "$candidate/sora/$totalSize/$token"
                val req = Request.Builder()
                    .url(segUrl)
                    .header("Referer", "https://abysscdn.com/")
                    .build()
                val result = runCatching {
                    val resp = client.newCall(req).execute()
                    if (!resp.isSuccessful) {
                        resp.close()
                        null
                    } else {
                        val source = resp.body?.source()
                        if (source == null) {
                            resp.close()
                            null
                        } else {
                            resp to source
                        }
                    }
                }.getOrNull()

                if (result != null) {
                    resolvedBaseUrl = candidate
                    return result
                }
            }
            return null
        }

        private fun schedulePrefetch(nextIndex: Int) {
            val nextSegStart = nextIndex.toLong() * FRAGMENT_SIZE
            if (nextSegStart > endByteInclusive) return
            if (prefetchCache.containsKey(nextIndex)) return
            if (!prefetchInFlight.add(nextIndex)) return

            prefetchExecutor.submit {
                try {
                    val bytes = fetchSegment(nextIndex)
                    if (bytes.isNotEmpty()) {
                        prefetchCache[nextIndex] = bytes
                    }
                } finally {
                    prefetchInFlight.remove(nextIndex)
                }
            }
        }

        /** Tải trọn segment vào RAM — dùng riêng cho prefetch chạy nền (không cần độ trễ thấp).
         * Cũng thử domain đã chốt trước, rồi lần lượt các domain còn lại — xem [openSegmentStream].
         */
        private fun fetchSegment(index: Int): ByteArray {
            val ordered = resolvedBaseUrl?.let { resolved ->
                listOf(resolved) + baseUrls.filter { it != resolved }
            } ?: baseUrls

            for (candidate in ordered) {
                val path = "/mp4/$md5Id/$resId/$totalSize/$FRAGMENT_SIZE/$index"
                val token = tokenFor(path)
                val segUrl = "$candidate/sora/$totalSize/$token"
                val req = Request.Builder()
                    .url(segUrl)
                    .header("Referer", "https://abysscdn.com/")
                    .build()
                val bytes = runCatching {
                    client.newCall(req).execute().use { resp ->
                        if (!resp.isSuccessful) null else resp.body?.bytes()
                    }
                }.getOrNull()

                if (bytes != null) {
                    resolvedBaseUrl = candidate
                    return bytes
                }
            }
            return ByteArray(0)
        }

        private fun tokenFor(path: String): String {
            val key = md5HexOfDigits(totalSize)
            val encrypted = aesCtrEncryptToIso(path, key)
            return doubleBase64(encrypted)
        }

        private fun md5HexOfDigits(value: Long): String {
            val bytes = value.toString().map { c ->
                if (c.isDigit()) c.digitToInt().toByte() else c.code.toByte()
            }.toByteArray()
            val digest = java.security.MessageDigest.getInstance("MD5").digest(bytes)
            return digest.joinToString("") { "%02x".format(it) }
        }

        private fun aesCtrEncryptToIso(data: String, keyHex: String): String {
            val keyBytes = keyHex.toByteArray(Charsets.UTF_8)
            val iv = keyBytes.copyOfRange(0, 16)
            val cipher = Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(keyBytes, "AES"), IvParameterSpec(iv))
            val encrypted = cipher.doFinal(data.toByteArray(Charsets.UTF_8))
            return String(encrypted, Charsets.ISO_8859_1)
        }

        private fun doubleBase64(input: String): String {
            val first = Base64.getEncoder().encodeToString(input.toByteArray(Charsets.ISO_8859_1)).replace("=", "")
            return Base64.getEncoder().encodeToString(first.toByteArray()).replace("=", "")
        }
    }
}
  
 
