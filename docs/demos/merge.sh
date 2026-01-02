GIF_IN="../kingfisher-usage-access-map-01.gif"
WEBM_IN="pw-out/066d10b5ae5d3603dacd69417a8227c6.webm"
OUT_GIF="../kingfisher-usage-access-map-01+accessmap.gif"

# 1) Normalize GIF -> MP4 (H.264, fixed fps/size)
ffmpeg -y -i "$GIF_IN" \
  -vf "fps=12,scale=960:-2:flags=lanczos" \
  -an -c:v libx264 -pix_fmt yuv420p -crf 18 -preset veryfast \
  gif_part.mp4

# 2) Normalize WEBM -> MP4 (same settings)
ffmpeg -y -i "$WEBM_IN" \
  -vf "fps=12,scale=960:-2:flags=lanczos" \
  -an -c:v libx264 -pix_fmt yuv420p -crf 18 -preset veryfast \
  webm_part.mp4

# 3) Concatenate via filter (video-only; reliable)
ffmpeg -y -i gif_part.mp4 -i webm_part.mp4 \
  -filter_complex "[0:v][1:v]concat=n=2:v=1:a=0[v]" \
  -map "[v]" -c:v libx264 -pix_fmt yuv420p -crf 18 -preset veryfast \
  combined.mp4

# 4) Convert combined MP4 -> GIF (single palette across whole thing)
ffmpeg -y -i combined.mp4 \
  -vf "fps=12,scale=960:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=256[p];[s1][p]paletteuse=dither=bayer" \
  "$OUT_GIF"

echo "Wrote: $OUT_GIF"
