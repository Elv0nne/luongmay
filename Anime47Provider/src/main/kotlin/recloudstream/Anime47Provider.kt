package recloudstream

import android.content.SharedPreferences
import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.lagradost.cloudstream3.Actor
import com.lagradost.cloudstream3.ActorData
import com.lagradost.cloudstream3.CommonActivity
import com.lagradost.cloudstream3.DubStatus
import com.lagradost.cloudstream3.ErrorLoadingException
import com.lagradost.cloudstream3.HomePageResponse
import com.lagradost.cloudstream3.LoadResponse
import com.lagradost.cloudstream3.MainAPI
import com.lagradost.cloudstream3.MainPageData
import com.lagradost.cloudstream3.MainPageRequest
import com.lagradost.cloudstream3.Score
import com.lagradost.cloudstream3.SearchResponse
import com.lagradost.cloudstream3.SubtitleFile
import com.lagradost.cloudstream3.TvType
import com.lagradost.cloudstream3.addDubStatus
import com.lagradost.cloudstream3.app
import com.lagradost.cloudstream3.mainPageOf
import com.lagradost.cloudstream3.network.CloudflareKiller
import com.lagradost.cloudstream3.newAnimeLoadResponse
import com.lagradost.cloudstream3.newAnimeSearchResponse
import com.lagradost.cloudstream3.newEpisode
import com.lagradost.cloudstream3.newHomePageResponse
import com.lagradost.cloudstream3.utils.ExtractorLink
import com.lagradost.cloudstream3.utils.ExtractorLinkType
import com.lagradost.cloudstream3.utils.Qualities
import com.lagradost.cloudstream3.utils.newExtractorLink
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.withLock
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

private val mapper: ObjectMapper = jacksonObjectMapper().apply {
    configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
}

private fun toJson(value: Any?): String {
    return try {
        mapper.writeValueAsString(value)!!
    } catch (e: Exception) {
        value.toString()
    }
}

class Anime47Provider : MainAPI() {

    override var mainUrl = "https://anime47.best"
    private val apiBaseUrl = "https://anime47.love/api"
    override var name = "Anime47"
    override val hasMainPage = true
    override var lang = "vi"
    override val hasDownloadSupport = true
    override val supportedTypes = setOf(TvType.Anime, TvType.Cartoon)

    private val interceptor = CloudflareKiller()
    private var cachedToken: String? = null

    private val prefs: SharedPreferences?
        get() {
            val activity = CommonActivity.activity ?: return null
            return activity.getSharedPreferences("anime47_prefs", 0)
        }

    override val mainPage: List<MainPageData> = mainPageOf(
        "/anime/filter?lang=vi&sort=latest" to "Anime Mới Cập Nhật",
        "/anime/filter?lang=vi&sort=rating" to "Top Đánh Giá",
        "/anime/filter?lang=vi&type=tv" to "Anime TV",
        "/anime/filter?lang=vi&type=movie" to "Anime Movie"
    )

    private val subtitleLanguageMap: Map<String, List<String>> = mapOf(
        "Vietnamese" to listOf("tiếng việt", "vietnamese", "vietsub", "viet", "vi"),
        "English" to listOf("tiếng anh", "english", "engsub", "eng", "en")
    )

    // ===================== Helper methods =====================

    private fun fixUrl(url: String?): String? {
        if (url.isNullOrBlank()) return null
        if (url.contains("via.placeholder.com", ignoreCase = true)) return null
        if (url.startsWith("http", ignoreCase = true)) return url
        if (url.startsWith("//")) return "https:$url"

        val path = if (url.startsWith("/")) url else "/$url"
        return if (mainUrl.startsWith("http", ignoreCase = true)) {
            "$mainUrl$path"
        } else {
            "https:$mainUrl$path"
        }
    }

    private fun createSearchResponse(
        title: String,
        poster: String?,
        link: String,
        year: Int? = null,
        episodesStr: String? = null
    ): SearchResponse {
        val episodes: Int? = episodesStr?.let { str ->
            val digitsOnly = str.filter { it.isDigit() }
            digitsOnly.toIntOrNull()
        }

        return newAnimeSearchResponse(title, link, TvType.Anime) {
            this.posterUrl = fixUrl(poster)
            this.year = year
            if (episodes != null) {
                addDubStatus(DubStatus.Subbed, episodes)
            }
        }
    }

    private fun toTvType(detail: DetailPost): TvType {
        // Lưu ý: luôn trả về TvType.Anime (hoặc Cartoon) thay vì TvType.AnimeMovie / TvType.OVA.
        // Lý do: CloudStream hiển thị UI "single play" (không có danh sách tập) cho các
        // TvType thuộc nhóm Movie/OVA, nên nếu một "movie" trên Anime47 thực chất có nhiều
        // tập/phần (rất phổ biến với OVA, special, hoặc movie nhiều phần), toàn bộ các tập
        // từ tập 2 trở đi sẽ bị ẩn khỏi người dùng ("mất tập"). Dùng TvType.Anime cho mọi
        // trường hợp để app luôn hiển thị danh sách tập đầy đủ, kể cả khi chỉ có 1 tập.
        return when {
            detail.title != null && detail.title.contains("Hoạt Hình Trung Quốc", ignoreCase = true) -> TvType.Cartoon
            else -> TvType.Anime
        }
    }

    private fun mapSubtitleLabel(label: String): String {
        val trimmedLower = label.trim().lowercase(java.util.Locale.ROOT)
        if (trimmedLower.isBlank()) return "Subtitle"

        for ((standardName, keywords) in subtitleLanguageMap) {
            if (keywords.any { trimmedLower.contains(it) }) {
                return standardName
            }
        }

        val trimmed = label.trim()
        return if (trimmed.isNotEmpty()) {
            val firstChar = trimmed[0]
            val firstCharUpper = if (firstChar.isLowerCase()) {
                firstChar.titlecase(java.util.Locale.ROOT)
            } else {
                firstChar.toString()
            }
            firstCharUpper + trimmed.substring(1)
        } else {
            trimmed
        }
    }

    private fun findMpegTsOffset(data: ByteArray): Int {
        val packetSize = 188
        val minLen = packetSize * 3
        if (data.size < minLen) return -1

        for (i in 0 until (data.size - minLen)) {
            if (data[i] == 0x47.toByte() &&
                data[i + packetSize] == 0x47.toByte() &&
                data[i + packetSize * 2] == 0x47.toByte()
            ) {
                return i
            }
        }
        return -1
    }

    // Token từ Anime47 có thời hạn ngắn (JWT hết hạn sau một khoảng thời gian).
    // Trước đây token được cache mãi mãi trong biến instance (cachedToken) và không
    // bao giờ được làm mới, dẫn tới lỗi: xem được vài tập/video rồi API bắt đầu trả
    // về "PRIVATE_MODE" (token đã hết hạn) và app quăng lỗi yêu cầu người dùng tự vào
    // cài đặt đăng nhập lại. Sửa: khi phát hiện token cũ không còn dùng được, tự động
    // login lại bằng email/password đã lưu (forceRefresh = true), hoàn toàn trong nền,
    // và chỉ retry request một lần thay vì bắt người dùng thao tác thủ công.
    private val tokenMutex = kotlinx.coroutines.sync.Mutex()

    private suspend fun ensureToken(forceRefresh: Boolean = false): String? {
        if (!forceRefresh) {
            val existing = cachedToken
            if (!existing.isNullOrBlank()) {
                return existing
            }
        }

        // Mutex tránh trường hợp nhiều coroutine (vd. loadLinks chạy song song cho
        // nhiều episodeId) cùng phát hiện token hết hạn và spam login song song.
        return tokenMutex.withLock {
            // Sau khi giành được lock, kiểm tra lại: có thể một coroutine khác đã
            // login lại thành công trong lúc chờ, nên không cần login lại lần nữa.
            if (!forceRefresh) {
                val existing = cachedToken
                if (!existing.isNullOrBlank()) {
                    return@withLock existing
                }
            }

            val email = prefs?.getString("anime47_email", "") ?: ""
            val password = prefs?.getString("anime47_password", "") ?: ""

            if (email.isBlank() || password.isBlank()) {
                return@withLock null
            }

            try {
                val body = toJson(LoginRequest(email, password))
                    .toRequestBody("application/json".toMediaTypeOrNull())

                val response = app.post(
                    "$apiBaseUrl/auth/login",
                    headers = mapOf(
                        "origin" to mainUrl,
                        "referer" to "$mainUrl/"
                    ),
                    requestBody = body,
                    interceptor = interceptor,
                    timeout = 15000
                )

                val loginResponse: LoginResponse = mapper.readValue(
                    response.text,
                    object : TypeReference<LoginResponse>() {}
                )
                val newToken = loginResponse.access_token
                if (!newToken.isNullOrBlank()) {
                    cachedToken = newToken
                }
                newToken
            } catch (e: Exception) {
                null
            }
        }
    }

    private suspend fun getAuthHeaders(forceRefresh: Boolean = false): Map<String, String> {
        val token = ensureToken(forceRefresh)
        return if (token != null) {
            mapOf("Authorization" to "Bearer $token")
        } else {
            emptyMap()
        }
    }

    private fun looksExpiredOrUnauthorized(text: String): Boolean {
        return text.contains("\"PRIVATE_MODE\"") ||
            text.contains("\"UNAUTHORIZED\"", ignoreCase = true) ||
            text.contains("\"unauthorized\"", ignoreCase = true) ||
            text.contains("\"TOKEN_EXPIRED\"", ignoreCase = true) ||
            text.contains("jwt expired", ignoreCase = true)
    }

    private suspend inline fun <reified T> fetchApi(url: String): T {
        val headers = getAuthHeaders()
        val firstResponse = app.get(
            url,
            headers = headers,
            interceptor = interceptor,
            timeout = 15000
        )

        var text = firstResponse.text
        val hadToken = headers.containsKey("Authorization")

        // Token cũ không còn hợp lệ (hết hạn hoặc bị thu hồi) hoặc request trả về mã
        // 401: xoá cache, ép đăng nhập lại một lần rồi thử lại request thay vì bắt
        // người dùng tự vào cài đặt đăng nhập lại.
        val looksStale = looksExpiredOrUnauthorized(text) || firstResponse.code == 401
        if (looksStale) {
            cachedToken = null
            val retryHeaders = getAuthHeaders(forceRefresh = true)

            if (retryHeaders.containsKey("Authorization")) {
                text = app.get(
                    url,
                    headers = retryHeaders,
                    interceptor = interceptor,
                    timeout = 15000
                ).text
            } else if (!hadToken) {
                // Không có tài khoản đã lưu từ đầu (chưa đăng nhập) -> giữ nguyên lỗi gốc.
            }
        }

        if (looksExpiredOrUnauthorized(text)) {
            throw ErrorLoadingException("Trang web yêu cầu đăng nhập. Vui lòng mở cài đặt tiện ích để cấu hình tài khoản.")
        }

        return mapper.readValue(text, object : TypeReference<T>() {})
    }

    override suspend fun getMainPage(
        page: Int,
        request: MainPageRequest
    ): HomePageResponse {
        val url = "$apiBaseUrl${request.data}&page=$page"

        val response: ApiFilterResponse? = try {
            fetchApi(url)
        } catch (e: ErrorLoadingException) {
            throw e
        } catch (e: Exception) {
            null
        }

        val posts = response?.data?.posts
            ?: throw ErrorLoadingException("Cấu trúc dữ liệu trang chủ đã thay đổi hoặc tài khoản chưa kích hoạt.")

        val items = posts.mapNotNull { post ->
            val link = fixUrl(post.link) ?: return@mapNotNull null
            createSearchResponse(
                post.title,
                post.poster,
                link,
                post.year?.toIntOrNull(),
                post.current_episode ?: post.episodes
            )
        }

        return newHomePageResponse(request.name, items, items.size >= 24)
    }

    override suspend fun search(query: String): List<SearchResponse> {
        val encoded = java.net.URLEncoder.encode(query, "UTF-8")
        val url = "$apiBaseUrl/search/full/?lang=vi&keyword=$encoded&page=1"

        val response: ApiSearchResponse? = try {
            fetchApi(url)
        } catch (e: ErrorLoadingException) {
            throw e
        } catch (e: Exception) {
            null
        }

        val results = response?.results ?: return emptyList()

        return results.mapNotNull { item ->
            val link = fixUrl(item.link) ?: return@mapNotNull null
            createSearchResponse(
                item.title,
                item.image,
                link,
                null,
                item.current_episode ?: item.episodes
            )
        }
    }

    override suspend fun load(url: String): LoadResponse {
        val animeId = Regex("(\\d+)(?:\\.html|/)?$")
            .find(url.trimEnd('/'))
            ?.groupValues
            ?.get(1)

        if (animeId.isNullOrBlank() || animeId.toIntOrNull() == null) {
            throw IllegalArgumentException("Invalid anime ID from URL")
        }

        try {
            val (infoResponse, episodeResponse, recsResponse) = coroutineScope {
                val infoTask = async {
                    fetchApi<ApiDetailResponse>("$apiBaseUrl/anime/info/$animeId?lang=vi")
                }
                val episodesTask = async {
                    fetchApi<ApiEpisodeResponse>("$apiBaseUrl/anime/$animeId/episodes?lang=vi")
                }
                val recsTask = async {
                    fetchApi<ApiRecommendationResponse>("$apiBaseUrl/anime/info/$animeId/recommendations?lang=vi")
                }
                Triple(infoTask.await(), episodesTask.await(), recsTask.await())
            }

            val detail = infoResponse?.data ?: throw IOException("Data is null")

            val title = detail.title ?: "Unknown Title"
            val posterUrl = fixUrl(detail.poster)
            val plot = detail.description
            val tags = detail.genres
                ?.mapNotNull { it.name }
                ?.filter { it.isNotBlank() }
            val year = detail.year?.toIntOrNull()
            val tvType = toTvType(detail)
            val score = detail.score?.toString()?.let { Score.from10(it) }

            val actors = detail.characters?.mapNotNull { character ->
                val name = character.name ?: return@mapNotNull null
                ActorData(
                    Actor(name, fixUrl(character.image_url)),
                    roleString = character.role
                )
            }

            // LƯU Ý (fix lỗi "ưu tiên nguồn"/Nguồn luôn chỉ hiện "Anime47"):
            // Trước đây bước flatten này chỉ giữ lại EpisodeListItem (id, number, title) và
            // BỎ MẤT team_name (tên nhóm sub: Kanefusa, OliviaSub, Yamisora, Koga Fansub, ...)
            // của EpisodeTeam chứa nó. Do đó ở loadLinks(), app không còn biết một id thuộc
            // team nào nữa, và tên nguồn hiển thị trong popup "Nguồn" chỉ còn lại tên chung
            // của provider ("Anime47") thay vì "TênTeam | FE"/"TênTeam | HY" như dữ liệu gốc.
            // Sửa: giữ lại team_name song song với từng id bằng EpisodeSourceRef, rồi nhúng
            // cả danh sách (id, team) vào "data" của tập thay vì chỉ danh sách id.
            val episodeItems = episodeResponse?.teams
                ?.flatMap { team ->
                    team.groups.flatMap { group ->
                        group.episodes.map { ep -> Triple(ep, team.team_name, group.name) }
                    }
                }
                ?.filter { (ep, _, _) -> ep.number != null }

            val episodes = if (episodeItems != null) {
                episodeItems
                    .groupBy { (ep, _, _) -> ep.number!! }
                    .map { (number, items) ->
                        val refs = items
                            .map { (ep, teamName, _) -> EpisodeSourceRef(ep.id, teamName) }
                            .distinctBy { it.id }
                        val data = toJson(refs)
                        newEpisode(data) {
                            this.name = "Tập $number"
                            this.episode = number
                        }
                    }
                    .sortedBy { it.episode }
            } else {
                emptyList()
            }

            val recommendations = recsResponse?.data?.mapNotNull { item ->
                val link = fixUrl(item.link) ?: return@mapNotNull null
                createSearchResponse(
                    item.title ?: "",
                    item.poster,
                    link,
                    item.year?.toIntOrNull(),
                    item.current_episode ?: item.episodes
                )
            }

            return newAnimeLoadResponse(title, url, tvType) {
                this.posterUrl = posterUrl
                this.plot = plot
                this.tags = tags
                this.year = year
                this.score = score
                this.actors = actors
                this.recommendations = recommendations
                this.episodes = mutableMapOf(DubStatus.Subbed to episodes)
            }
        } catch (e: Exception) {
            throw IOException("Lỗi tải thông tin phim: ${e.message}", e)
        }
    }

    override suspend fun loadLinks(
        data: String,
        isCasting: Boolean,
        subtitleCallback: (SubtitleFile) -> Unit,
        callback: (ExtractorLink) -> Unit
    ): Boolean {
        // "data" giờ có thể là JSON list of EpisodeSourceRef([{"id":..,"team":..}, ...]) mới,
        // hoặc list of Int cũ (dữ liệu tập đã lưu/cache từ trước khi sửa lỗi này) — vẫn phải
        // đọc được để không vỡ tập đã bookmark, chỉ là sẽ không có tên team trong trường hợp đó.
        val episodeRefs: List<EpisodeSourceRef> = try {
            if (data.startsWith("[")) {
                try {
                    mapper.readValue(data, object : TypeReference<List<EpisodeSourceRef>>() {})
                } catch (e: Exception) {
                    mapper.readValue(data, object : TypeReference<List<Int>>() {})
                        .map { EpisodeSourceRef(it, null) }
                }
            } else {
                listOf(EpisodeSourceRef(data.toInt(), null))
            }
        } catch (e: Exception) {
            return false
        }

        if (episodeRefs.isEmpty()) return false

        val loaded = AtomicBoolean(false)
        val referer = "$mainUrl/"

        coroutineScope {
            episodeRefs.map { ref ->
                async {
                    try {
                        val watchResponse: ApiWatchResponse? =
                            fetchApi("$apiBaseUrl/anime/watch/episode/${ref.id}?lang=vi")

                        val streams = watchResponse?.streams ?: return@async
                        // Tên team (Kanefusa, OliviaSub, Yamisora, Koga Fansub, ...) đi kèm id
                        // tập từ EpisodeSourceRef, dùng làm tiền tố "Nguồn" giống app gốc, thay
                        // vì luôn để trống và mọi link rơi chung vào một nguồn "Anime47".
                        val teamLabel = ref.team?.trim()?.takeIf { it.isNotBlank() }

                        for (stream in streams) {
                            val url = stream.url
                            val rawServerName = stream.server_name
                            val serverName = if (!teamLabel.isNullOrBlank()) {
                                if (!rawServerName.isNullOrBlank()) "$teamLabel | $rawServerName" else teamLabel
                            } else {
                                rawServerName
                            }

                            if (url.isNullOrBlank()) continue

                            // Server "HY" (Hydrax/Abyss.to) không trả về m3u8 thật, mà là một trang
                            // embed chứa metadata mã hóa AES-CTR (xem HydraxExtractor.kt). Phải đi
                            // qua HydraxExtractor + HydraxInterceptor thay vì coi url là m3u8 trực tiếp.
                            if (HydraxExtractor.isHydraxUrl(url)) {
                                try {
                                    val hydraxLinks = HydraxExtractor.getLinks(
                                        streamUrl = url,
                                        providerName = this@Anime47Provider.name,
                                        serverName = serverName,
                                        referer = referer
                                    )
                                    hydraxLinks.forEach { callback(it) }
                                    if (hydraxLinks.isNotEmpty()) loaded.set(true)
                                } catch (e: Exception) {
                                    // bỏ qua lỗi riêng của HY, không chặn các server khác
                                }

                                stream.subtitles?.forEach { subtitle ->
                                    if (!subtitle.file.isNullOrBlank()) {
                                        val label = mapSubtitleLabel(subtitle.label ?: "Vietnamese")
                                        subtitleCallback(SubtitleFile(label, subtitle.file))
                                    }
                                }
                                continue
                            }

                            // Chấp nhận mọi server có URL hợp lệ (FE, HY, hoặc bất kỳ server nào khác),
                            // thay vì chỉ giới hạn ở "FE"/jwplayer và loại trừ "HY" như logic gốc.
                            val headers = mutableMapOf(
                                "Referer" to referer,
                                "User-Agent" to "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
                                "sec-ch-ua" to "\"Chromium\";v=\"120\", \"Not?A_Brand\";v=\"24\"",
                                "sec-ch-ua-mobile" to "?1",
                                "sec-ch-ua-platform" to "\"Android\""
                            )

                            if (url.contains("vlogphim.net")) {
                                headers["Origin"] = referer
                                try {
                                    val host = java.net.URL(url).host
                                    headers["authority"] = host
                                } catch (e: Exception) {
                                    headers["authority"] = "pl.vlogphim.net"
                                }
                            }

                            val link = newExtractorLink(
                                this@Anime47Provider.name,
                                serverName ?: this@Anime47Provider.name,
                                url,
                                ExtractorLinkType.M3U8
                            ) {
                                this.referer = referer
                                this.headers = headers
                                this.quality = Qualities.Unknown.value
                            }

                            callback(link)
                            loaded.set(true)

                            stream.subtitles?.forEach { subtitle ->
                                if (!subtitle.file.isNullOrBlank()) {
                                    val label = mapSubtitleLabel(subtitle.label ?: "Vietnamese")
                                    subtitleCallback(SubtitleFile(label, subtitle.file))
                                }
                            }
                        }
                    } catch (e: Exception) {
                        // bỏ qua lỗi từng episode riêng lẻ
                    }
                }
            }.awaitAll()
        }

        return loaded.get()
    }

    /**
     * LƯU Ý: Class ẩn danh gốc "Anime47Provider$getVideoInterceptor$1" (triển khai Interceptor)
     * KHÔNG có trong file .cs3 / bản decompile được cung cấp, nên phần dưới đây được suy luận
     * hợp lý từ tên hàm findMpegTsOffset() và regex domain, không phải dịch chính xác 100% từ bytecode gốc.
     * Vui lòng kiểm tra và điều chỉnh lại nếu bạn có bản gốc chính xác hơn.
     */
    override fun getVideoInterceptor(extractorLink: ExtractorLink): Interceptor? {
        // Link Hydrax/Abyss trỏ về host relay nội bộ (xem HydraxExtractor.buildRelayUrl);
        // mọi request Range của player phải đi qua HydraxInterceptor để dịch sang giao thức
        // segment-token thật của Abyss. Không chạm vào logic CDN nonprofit.asia bên dưới.
        if (extractorLink.url.contains(HydraxExtractor.RELAY_HOST)) {
            return HydraxInterceptor
        }

        val cdnRegex = Regex("nonprofit\\.asia|cdn\\d+\\.nonprofit")

        return Interceptor { chain ->
            val request = chain.request()
            val response = chain.proceed(request)

            if (!cdnRegex.containsMatchIn(request.url.toString())) {
                return@Interceptor response
            }

            val body = response.body ?: return@Interceptor response
            val bytes = body.bytes()
            val offset = findMpegTsOffset(bytes)

            val fixedBytes = if (offset > 0) bytes.copyOfRange(offset, bytes.size) else bytes

            response.newBuilder()
                .body(fixedBytes.toResponseBody(body.contentType()))
                .build()
        }
    }
    // ===================== Data classes (API models) =====================

    data class LoginRequest(
        val login: String,
        val password: String
    )

    data class LoginResponse(
        val access_token: String?,
        val refresh_token: String?
    )

    data class GenreInfo(
        val name: String?
    )

    data class CharacterInfo(
        val name: String?,
        val role: String?,
        val image_url: String?
    )

    data class Post(
        val id: Int,
        val title: String,
        val slug: String,
        val link: String,
        val poster: String?,
        val episodes: String?,
        val current_episode: String?,
        val type: String?,
        val year: String?
    )

    data class ApiFilterData(
        val posts: List<Post>? = null
    )

    data class ApiFilterResponse(
        val success: Boolean? = null,
        val message: String? = null,
        val data: ApiFilterData? = null
    )

    data class VideoItem(
        val url: String?
    )

    data class DetailPost(
        val id: Int,
        val title: String?,
        val description: String?,
        val poster: String?,
        val cover: String?,
        val type: String?,
        val year: String?,
        val genres: List<GenreInfo>?,
        val videos: List<VideoItem>?,
        val score: Double?,
        val characters: List<CharacterInfo>?
    )

    data class ApiDetailResponse(
        val data: DetailPost
    )

    data class EpisodeListItem(
        val id: Int,
        val number: Int?,
        val title: String?
    )

    // Gắn tên team (Kanefusa, OliviaSub, Yamisora, Koga Fansub, ...) với từng episode id,
    // được nhúng vào "data" của Episode ở load() và đọc lại ở loadLinks() để dựng đúng
    // tên nguồn "TeamName | ServerName" thay vì luôn chỉ hiện tên provider "Anime47".
    data class EpisodeSourceRef(
        val id: Int,
        val team: String?
    )

    data class EpisodeGroup(
        val name: String?,
        val episodes: List<EpisodeListItem>
    )

    data class EpisodeTeam(
        val team_name: String?,
        val groups: List<EpisodeGroup>
    )

    data class ApiEpisodeResponse(
        val teams: List<EpisodeTeam>
    )

    data class SubtitleItem(
        val file: String?,
        val label: String?
    )

    data class Stream(
        val url: String?,
        val server_name: String?,
        val player_type: String?,
        val subtitles: List<SubtitleItem>?
    )

    data class WatchAnimeInfo(
        val id: Int,
        val title: String?,
        val slug: String?,
        val thumbnail: String?
    )

    data class ApiWatchResponse(
        val id: Int?,
        val streams: List<Stream>?,
        val anime: WatchAnimeInfo?
    )

    data class RecommendationItem(
        val id: Int,
        val title: String?,
        val link: String?,
        val poster: String?,
        val type: String?,
        val year: String?,
        val episodes: String?,
        val current_episode: String?
    )

    data class ApiRecommendationResponse(
        val data: List<RecommendationItem>?
    )

    data class SearchItem(
        val id: Int,
        val title: String,
        val link: String,
        val image: String?,
        val type: String?,
        val episodes: String?,
        val current_episode: String?
    )

    data class ApiSearchResponse(
        val results: List<SearchItem>?,
        val has_more: Boolean?
    )
}
 
 
