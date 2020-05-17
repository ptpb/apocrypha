typedef struct mime_entry {
  const char *ext;
  const char *type;
} mime_entry_t;

static mime_entry_t
mime_types[] = {
  // "common"
  {"html", "text/html"},
  {"txt", "text/plain"},
  {"css", "text/css"},
  {"jpeg", "image/jpeg"},
  {"jpg", "image/jpeg"},
  {"gif", "image/gif"},
  {"js", "application/javascript"},
  {"png", "image/png"},
  {"svg", "image/svg+xml"},
  {"svgz", "image/svg+xml"},
  {"webp", "image/webp"},
  {"json", "application/json"},
  {"bin", "application/octet-stream"},
  {"mp3", "audio/mpeg"},
  {"mp4", "video/mp4"},
  {"webm", "video/webm"},
  {"pdf", "application/pdf"},
  // unlikely
  {"xml", "text/xml"},
  {"atom", "application/atom+xml"},
  {"rss", "application/rss+xml"},
  {"mov", "video/quicktime"},
  {"xhtml", "application/xhtml+xml"},
  {"tif", "image/tiff"},
  {"tiff", "image/tiff"},
  {"ico", "image/x-icon"},
  {"bmp", "image/bmp2"},
  {"woff", "font/woff"},
  {"woff2", "font/woff2"},
  {"ogg", "audio/ogg"},
  {"m4a", "audio/x-m4a"},
  {"mpg", "video/mpeg"},
  {"mpeg", "video/mpeg"},
};
