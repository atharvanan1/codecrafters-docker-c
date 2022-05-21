#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include "cJSON.h"
#include "file_ops.h"
#include "registry_ops.h"
#include "logger.h"

#define MAX_IMAGE_NAME 100
#define MAX_URL 4096
#define MAX_TOKEN 4096
#define MAX_LAYERS 50

struct shaLayer {
    char sha_value[73];
    char file_path[PATH_MAX];
};

struct JsonResStruct {
    char *memory;
    size_t size;
};

struct TarFile {
    const char *filename;
    FILE *stream;
};

struct CURLdbg_data {
    char trace_ascii; /* 1 or 0 */
};

/* CURL debug functions */
static void
CURLdbg_dump(const char *text,
          FILE *stream, unsigned char *ptr, size_t size,
          char nohex)
{
    size_t i;
    size_t c;

    unsigned int width = 0x10;

    if(nohex)
        /* without the hex output, we can fit more on screen */
        width = 0x40;

    fprintf(stream, "%s, %10.10lu bytes (0x%8.8lx)\n",
            text, (unsigned long)size, (unsigned long)size);

    for(i = 0; i<size; i += width) {

        fprintf(stream, "%4.4lx: ", (unsigned long)i);

        if(!nohex) {
            /* hex not disabled, show it */
            for(c = 0; c < width; c++)
                if(i + c < size)
                    fprintf(stream, "%02x ", ptr[i + c]);
                else
                    fputs("   ", stream);
        }

        for(c = 0; (c < width) && (i + c < size); c++) {
            /* check for 0D0A; if found, skip past and start a new line of output */
            if(nohex && (i + c + 1 < size) && ptr[i + c] == 0x0D &&
               ptr[i + c + 1] == 0x0A) {
                i += (c + 2 - width);
                break;
            }
            fprintf(stream, "%c",
                    (ptr[i + c] >= 0x20) && (ptr[i + c]<0x80)?ptr[i + c]:'.');
            /* check again for 0D0A, to avoid an extra \n if it's at width */
            if(nohex && (i + c + 2 < size) && ptr[i + c + 1] == 0x0D &&
               ptr[i + c + 2] == 0x0A) {
                i += (c + 3 - width);
                break;
            }
        }
        fputc('\n', stream); /* newline */
    }
    fflush(stream);
}

static int
CURLdbg_trace(CURL *handle, curl_infotype type,
             char *data, size_t size,
             void *userp)
{
    struct CURLdbg_data *config = (struct CURLdbg_data *)userp;
    const char *text;
    (void)handle; /* prevent compiler warning */

    switch(type) {
        case CURLINFO_TEXT:
            fprintf(stderr, "== Info: %s", data);
            /* FALLTHROUGH */
        default: /* in case a new one is introduced to shock us */
            return 0;

        case CURLINFO_HEADER_OUT:
            text = "=> Send header";
            break;
        case CURLINFO_DATA_OUT:
            text = "=> Send data";
            break;
        case CURLINFO_SSL_DATA_OUT:
            text = "=> Send SSL data";
            break;
        case CURLINFO_HEADER_IN:
            text = "<= Recv header";
            break;
        case CURLINFO_DATA_IN:
            text = "<= Recv data";
            break;
        case CURLINFO_SSL_DATA_IN:
            text = "<= Recv SSL data";
            break;
    }

    CURLdbg_dump(text, stderr, (unsigned char *)data, size, config->trace_ascii);
    return 0;
}

/* Registry Operations */

///
/// \details This function was borrowed from https://curl.se/libcurl/c/getinmemory.html
/// \param contents Data to be written (Source)
/// \param size Size of each member
/// \param nmemb Number of members
/// \param userp Pointer to memory block (Destination)
/// \return Number of bytes written in memory
static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct JsonResStruct *mem = (struct JsonResStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) {
        /* out of memory! */
        log_msg(ERR, "not enough memory (realloc returned NULL)");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

///
/// \details This function was borrowed from https://curl.se/libcurl/c/ftpget.html
/// \param buffer Data to be written (Source)
/// \param size Size of each member
/// \param nmemb Number of members
/// \param TarFile Struct for file related operation
/// \return Number of bytes written to the file
static size_t
WriteFileCallback(void *buffer, size_t size, size_t nmemb, void *TarFile)
{
    struct TarFile *out = (struct TarFile *) TarFile;
    if (!out->stream) {
        /* open file for writing */
        out->stream = fopen(out->filename, "wb");
        if (!out->stream)
            return -1; /* failure, cannot open file to write */
    }
    size_t written = fwrite(buffer, size, nmemb, out->stream);
    return written;
}

///
/// \brief When provided with image name, this function
///        will prepend image name with "library/" (excluding quotes).
/// \example get_full_image_name("ubuntu:latest", ptr_to_image_name) -> ptr_to_image_name = "library/ubuntu"
/// \param image String containing name of image
/// \param image_name Pre-allocated string to be populated with appropriate image
///                   name
static void
get_full_image_name(char *image, char *image_name)
{
    size_t len = strlen(image);
    int i = 0;
    for (; i < len; i++) {
        if (*(image + i) == ':') {
            break;
        }
    }
    strcpy(image_name, "library/");
    strncat(image_name, image, i);
}

///
/// \brief When provided with image name, this function
///        will look for image digest if not found then "latest" is used
/// \param image String containing name of image
/// \param image_digest Pre-allocated string to be populated with appropriate image
///                     name
static void
get_image_digest(char *image, char *image_digest)
{
    size_t len = strlen(image);
    int i = 0;
    for(; i < len; i++) {
        if (*(image + i) == ':') {
            break;
        }
    }
    if (i >= len) {
        strcpy(image_digest, "latest");
        return;
    }
    strcpy(image_digest, image + i + 1);
}

/// \brief Perform a GET request
/// \param url URL to be used to GET request
/// \param auth_token Authentication Token for Bearer based authentication. Use NULL if no authentication
///                   is needed
/// \param response JSON response for GET request
/// \return CURLcode
CURLcode
get_request(char *url, char *auth_token, struct JsonResStruct *response)
{
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    if (auth_token != NULL) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, auth_token);
    }
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_msg(DBG, "GET request failed: %s",
                curl_easy_strerror(res));
    } else {
        log_msg(DBG, "curl: %lu bytes retrieved", (unsigned long)response->size);
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code >= 400) {
            log_msg(WARN, "GET Request failed with %ld", http_code);
            res = CURLE_HTTP_RETURNED_ERROR;
        }
    }
    curl_easy_cleanup(curl);
    return res;
}

///
/// \brief This function will get the authentication token from url and
///        place the auth token in auth_token
/// \param url URL for GET auth token request
/// \param auth_token Pointer to pre-allocated memory where token will be stored
/// \return 0 for success, -1 for error
static int
get_auth_json(char *url, char **auth_token)
{
    int ret = 0;
    struct JsonResStruct response;
    response.memory = malloc(1);
    response.size = 0;
    CURLcode res = get_request(url, NULL, &response);
    if (res == CURLE_OK) {
        cJSON *auth_json = cJSON_Parse(response.memory);
        cJSON *token = cJSON_GetObjectItemCaseSensitive(auth_json, "token");
        size_t token_len = strnlen(token->valuestring, MAX_TOKEN) + 1;
        *auth_token = (char *) malloc(sizeof(char) * token_len);
        strncpy(*auth_token, token->valuestring, token_len);
        cJSON_Delete(auth_json);
        log_msg(DBG, "Authentication token: %s\n", *auth_token);
    } else {
        ret = -1;
    }
    free(response.memory);
    return ret;
}

///
/// \brief This function will get layer sha for a given image
/// \param url URL to obtain image manifest
/// \param auth_token Pointer to where auth token is stored
/// \param num_layers Pointer to memory location where number of layer will be exported;
///                   to be used by user
/// \return Pointer to shaLayer information for all layers on success; NULL on error
static struct shaLayer **
get_image_layers(char *url, char* auth_token, int *num_layers)
{
    struct shaLayer **ret = NULL;
    struct JsonResStruct response;
    response.memory = malloc(1);
    response.size = 0;
    CURLcode res = get_request(url, auth_token, &response);
    if (res == CURLE_OK) {
        cJSON *manifest_json = cJSON_Parse(response.memory);
        cJSON *fsLayers = cJSON_GetObjectItemCaseSensitive(manifest_json, "fsLayers");
        if (fsLayers == NULL) {
            log_msg(ERR, "Invalid manifest data");
            return NULL;
        }
        *num_layers = cJSON_GetArraySize(fsLayers);
        struct shaLayer **layers = (struct shaLayer **) malloc(sizeof(struct shaLayer *) * *num_layers);
        // Allocate things for layers
        for (int i = 0; i < *num_layers; i++) {
            cJSON *item = cJSON_GetArrayItem(fsLayers, i);
            cJSON *blobSum = cJSON_GetObjectItemCaseSensitive(item, "blobSum");
            char * layer_sha_str = cJSON_GetStringValue(blobSum);
            layers[i] = (struct shaLayer *) malloc(sizeof(struct shaLayer));
            strncpy(layers[i]->sha_value, layer_sha_str, 73);
            log_msg(DBG, "Layer SHA value: %s", layers[i]->sha_value);
        }

        cJSON_Delete(manifest_json);
        ret = layers;
    } else {
        ret = NULL;
    }
    free(response.memory);
    return ret;
}

///
/// \brief Downloads a file provided by url to location referenced in TarFile.filename
/// \param url HTTP url for GET request to download the file
/// \param auth_token Pointer to memory where authentication token is saved
/// \param file struct TarFile with valid filename for saving the downloaded information
/// \return CURLcode
static CURLcode
download_file(char *url, char *auth_token, struct TarFile *file)
{
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, auth_token);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFileCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)file);
#ifdef DEBUG
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, CURLdbg_trace);
    struct CURLdbg_data config;
    config.trace_ascii = 1; /* enable ascii tracing */
    curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &config);
#endif
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);       // Suppress download information
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);   // Follows through redirections
    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        log_msg(ERR, "download_file failed: %s\n",
                curl_easy_strerror(res));
    }
    long size = 0;
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &size);
    log_msg(DBG, "Downloaded %ld bytes", size);
    curl_easy_cleanup(curl);
    return res;
}

///
/// \param file_path path to check if it exists
/// \return true if file exists on the file_path, otherwise false
static bool
check_if_file_exists(char* file_path)
{
    if (access(file_path, F_OK) == 0) {
        return true;
    } else {
        return false;
    }
}

///
/// \brief Downloads the image and associated layers
/// \param base_url Docker registry base url
/// \param auth_token Pointer to memory location where Authentication Token is saved
/// \param shaLayers Pointer to array of shaLayer information for each layer
/// \param dirname Directory to store the layer tarballs
/// \param num_layers Number of layers
/// \return
static int
download_image(char *base_url, char* auth_token, struct shaLayer** shaLayers, char *dirname, int num_layers)
{
    int res = 0;
    for (int i = 0; i < num_layers; i++)
    {
        char filename[PATH_MAX];
        snprintf(filename,
                 PATH_MAX,
                 "%s/%s.tar", dirname, shaLayers[i]->sha_value + 7);
        struct TarFile layerfile = {
                filename,
                NULL
        };

        strcpy(shaLayers[i]->file_path, filename);
        char url[MAX_URL];
        snprintf(url,
                 MAX_URL,
                 "%s%s", base_url, shaLayers[i]->sha_value);
        if (check_if_file_exists(filename)) {
            log_msg(INFO, "Layer %s: exists", shaLayers[i]->sha_value + 7);
            continue;
        } else {
            log_msg(INFO, "Layer %s: pulling at %s", shaLayers[i]->sha_value + 7, filename);
            res = download_file(url, auth_token, &layerfile);
            if (res < 0) {
                fprintf(stderr, "download_file() failed\n");
                return res;
            }
        }
    };
    sync();
    return res;
}

///
/// \brief Pulls an image from registry.hub.docker.com
/// \param image Image name eg. "ubuntu:latest" or "ubuntu:18.04"
/// \param rootfs_path Path to extract the layer blobs
/// \return 0 on success, -1 on error
int
pull_image(char *image, char *rootfs_path)
{
    char image_name[MAX_IMAGE_NAME] = {0};
    char image_digest[MAX_IMAGE_NAME] = {0};
    get_full_image_name(image, image_name);
    log_msg(DBG, "Image Name: %s", image_name);
    get_image_digest(image, image_digest);
    log_msg(DBG, "Image Digest: %s", image_digest);

    // Prepare pull directory
    char image_pull_dir[PATH_MAX] = {0};
    snprintf(image_pull_dir, PATH_MAX, "%s/%s",
             DOCKER_PERSIST, image_name);
    log_msg(DBG, "Pull image directory: %s", image_pull_dir);
    mkpath(image_pull_dir);
    mkdir(image_pull_dir, 0777);

    // Get auth
    char *auth_token = NULL;
    char auth_url[MAX_URL] = {0};
    snprintf(auth_url,
             MAX_URL,
             "https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", image_name);
    log_msg(DBG, "Authentication URL: %s", auth_url);
    int auth_res = get_auth_json(auth_url, &auth_token);
    if (auth_res < 0) {
        log_msg(ERR, "Failed to authenticate with docker registry");
        return -1;
    }

    // Fetch manifest
    struct shaLayer **shaLayers = NULL;
    int num_layers = 0;
    char manifest_url[MAX_URL] = {0};
    snprintf(manifest_url,
             MAX_URL,
             "https://registry.hub.docker.com/v2/%s/manifests/%s", image_name, image_digest);
    log_msg(DBG, "Manifest URL: %s", manifest_url);
    shaLayers = get_image_layers(manifest_url, auth_token, &num_layers);
    if (shaLayers == NULL) {
        log_msg(ERR, "Failed to get image manifest");
        return -1;
    }

    // Download layers
    log_msg(INFO, "Pulling %s:%s from registry.hub.docker.com", image_name, image_digest);
    char pull_blob_base_url[MAX_URL] = {0};
    snprintf(pull_blob_base_url,
             MAX_URL,
             "https://registry.hub.docker.com/v2/%s/blobs/", image_name);
    log_msg(DBG, "Pull Blob Base URL: %s", pull_blob_base_url);
    int download_res = download_image(pull_blob_base_url, auth_token, shaLayers, image_pull_dir, num_layers);
    if (download_res < 0) {
        log_msg(ERR, "Failed to download image");
        return -1;
    }

    // Extract layers
    for (int i = 0; i < num_layers; i++) {
        char cmd[8300] = {0};
        snprintf(cmd, 8300, "tar -xf %s -C %s >/dev/null 2>&1", shaLayers[i]->file_path, rootfs_path);
        log_msg(DBG, "Extract command: %s", cmd);
        int extract_res = system(cmd);
        if (extract_res < 0) {
            log_msg(ERR, "Failed to run following command\n%s", cmd);
            return -1;
        }
	    free(shaLayers[i]);
    }

    free(shaLayers);
    free(auth_token);
    return 0;
}
