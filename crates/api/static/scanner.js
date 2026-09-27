// Signal field for the landing page.
// The sweep math is adapted from the React Bits Scanner shader (MIT).
// Colors and the page wiring are this project's.

(function () {
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  document.querySelectorAll(".scanner").forEach(function (container) {
  const stage = container.closest(".landing, .map-stage") || container;
  const red = container.getAttribute("data-theme") === "red";

  const vertex = `#version 300 es
in vec2 position;
void main() {
  gl_Position = vec4(position, 0.0, 1.0);
}
`;

  const fragment = `#version 300 es
precision highp float;
uniform vec2 iResolution;
uniform float iTime;
uniform float uSpeed;
uniform float uSweepSpeed;
uniform float uSweepWidth;
uniform float uSweepFalloff;
uniform float uScale;
uniform float uFrequency;
uniform float uRipple;
uniform float uBandDensity;
uniform float uLineSharpness;
uniform float uGlow;
uniform float uColorSpread;
uniform float uBrightness;
uniform float uContrast;
uniform float uSoftness;
uniform float uVignette;
uniform float uOpacity;
uniform float uScanline;
uniform float uGrain;
uniform float uGrainIntensity;
uniform float uDirection;
uniform vec2 uMouse;
uniform float uMouseEnabled;
uniform float uMouseRadius;
uniform float uMouseStrength;
uniform float uMouseActive;
uniform vec3 uColor1;
uniform vec3 uColor2;
uniform vec3 uColor3;
out vec4 fragColor;

const float TAU = 6.2831853;

float signalField(vec2 p, float t) {
  float w = sin(p.x * 1.3 + t * 0.7);
  w += sin(p.y * 1.7 - t * 0.52) * 0.8;
  w += sin((p.x + p.y) * 0.9 + t * 0.91) * 0.6;
  w += sin((p.x - p.y) * 1.53 - t * 0.63) * 0.42;
  return w * 0.35;
}

vec3 palette(float f) {
  f = clamp(f, 0.0, 1.0);
  f = pow(f, uContrast);
  vec3 c = mix(uColor1, uColor2, smoothstep(0.08, 0.6, f));
  return mix(c, uColor3, smoothstep(0.68, 1.0, f));
}

float scanBand(float x, float aa, float sharp) {
  float v = mix(0.5, 0.5 + 0.5 * cos(x * TAU), aa);
  return pow(v, sharp);
}

void main() {
  float aspect = iResolution.x / iResolution.y;
  vec2 uv0 = (gl_FragCoord.xy * 2.0 - iResolution.xy) / iResolution.y;
  vec2 p = uv0 / max(uScale, 0.001);
  float t = iTime * uSpeed;

  float mouseBoost = 0.0;
  if (uMouseEnabled > 0.5) {
    vec2 mUv = vec2((uMouse.x * 2.0 - 1.0) * aspect, uMouse.y * 2.0 - 1.0);
    vec2 md = uv0 - mUv;
    float r = max(uMouseRadius, 0.001);
    mouseBoost = exp(-dot(md, md) / (r * r)) * uMouseStrength * uMouseActive;
  }

  float axis;
  if (uDirection < 0.5) axis = p.y;
  else if (uDirection < 1.5) axis = p.x;
  else axis = (p.x + p.y) * 0.70710678;

  float sig = signalField(p * uFrequency, t);
  float coord = axis + sig * uRipple;
  float phase = coord / max(uSweepWidth, 0.05) - t * uSweepSpeed;
  float sweep = pow(0.5 + 0.5 * cos(phase * TAU), max(uSweepFalloff, 0.1));
  float lc = coord * uBandDensity;
  float aa = 1.0 / (1.0 + uSoftness * fwidth(lc) * 3.0);
  aa = clamp(aa * (1.0 + mouseBoost * 0.6), 0.0, 1.0);

  float bodyBase = clamp(0.5 + 0.5 * sig, 0.0, 1.0);
  float body = bodyBase * bodyBase * uGlow * sweep;
  float sharp = max(uLineSharpness, 0.1);
  float split = uColorSpread * 0.16;
  float sweepMix = 0.38 + 0.62 * sweep;
  float fr = clamp(scanBand(lc + split, aa, sharp) * sweepMix + body, 0.0, 1.0);
  float fg = clamp(scanBand(lc, aa, sharp) * sweepMix + body, 0.0, 1.0);
  float fb = clamp(scanBand(lc - split, aa, sharp) * sweepMix + body, 0.0, 1.0);
  vec3 col = vec3(palette(fr).r, palette(fg).g, palette(fb).b);
  float inten = (fr + fg + fb) * 0.3333333 * uBrightness;
  inten *= 1.0 + mouseBoost * 0.9;
  if (uScanline > 0.5) {
    inten *= 1.0 - 0.18 * (0.5 + 0.5 * cos(gl_FragCoord.y * 1.7));
  }
  if (uGrain > 0.5) {
    float g = fract(sin(dot(gl_FragCoord.xy, vec2(12.9898, 78.233)) + iTime) * 43758.5453);
    inten += (g - 0.5) * uGrainIntensity;
  }
  inten *= clamp(1.0 - uVignette * smoothstep(0.55, 1.65, length(uv0)), 0.0, 1.0);
  inten = clamp(inten, 0.0, 1.0);
  float a = clamp(inten * uOpacity, 0.0, 1.0);
  fragColor = vec4(clamp(col, 0.0, 1.0) * a, a);
}`;

  const canvas = document.createElement("canvas");
  const gl = canvas.getContext("webgl2", {
    alpha: true,
    premultipliedAlpha: true,
    antialias: false,
    preserveDrawingBuffer: true,
  });
  if (!gl) return;

  function compile(type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      gl.deleteShader(shader);
      return null;
    }
    return shader;
  }

  const vs = compile(gl.VERTEX_SHADER, vertex);
  const fs = compile(gl.FRAGMENT_SHADER, fragment);
  if (!vs || !fs) return;
  const program = gl.createProgram();
  gl.attachShader(program, vs);
  gl.attachShader(program, fs);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) return;
  gl.useProgram(program);

  const buffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const position = gl.getAttribLocation(program, "position");
  gl.enableVertexAttribArray(position);
  gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);
  gl.enable(gl.BLEND);
  gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);

  function hex(value) {
    const match = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(value);
    if (!match) return [1, 1, 1];
    return [parseInt(match[1], 16) / 255, parseInt(match[2], 16) / 255, parseInt(match[3], 16) / 255];
  }

  const uniforms = {};
  for (const name of [
    "iResolution", "iTime", "uSpeed", "uSweepSpeed", "uSweepWidth", "uSweepFalloff",
    "uScale", "uFrequency", "uRipple", "uBandDensity", "uLineSharpness", "uGlow",
    "uColorSpread", "uBrightness", "uContrast", "uSoftness", "uVignette", "uOpacity",
    "uScanline", "uGrain", "uGrainIntensity", "uDirection", "uMouse", "uMouseEnabled",
    "uMouseRadius", "uMouseStrength", "uMouseActive", "uColor1", "uColor2", "uColor3",
  ]) {
    uniforms[name] = gl.getUniformLocation(program, name);
  }

  gl.uniform1f(uniforms.uSpeed, 0.45);
  gl.uniform1f(uniforms.uSweepSpeed, 0.22);
  gl.uniform1f(uniforms.uSweepWidth, 1.6);
  gl.uniform1f(uniforms.uSweepFalloff, 2.4);
  gl.uniform1f(uniforms.uScale, 1.35);
  gl.uniform1f(uniforms.uFrequency, 1.7);
  gl.uniform1f(uniforms.uRipple, 0.28);
  gl.uniform1f(uniforms.uBandDensity, 6);
  gl.uniform1f(uniforms.uLineSharpness, 1.5);
  gl.uniform1f(uniforms.uGlow, red ? 0.55 : 0.55);
  gl.uniform1f(uniforms.uColorSpread, red ? 0.4 : 0.45);
  gl.uniform1f(uniforms.uBrightness, red ? 1.05 : 1.35);
  gl.uniform1f(uniforms.uContrast, red ? 1.2 : 1.05);
  gl.uniform1f(uniforms.uSoftness, 1.1);
  gl.uniform1f(uniforms.uVignette, red ? 0.4 : 0.35);
  gl.uniform1f(uniforms.uOpacity, red ? 0.92 : 1);
  gl.uniform1f(uniforms.uScanline, 1);
  gl.uniform1f(uniforms.uGrain, 1);
  gl.uniform1f(uniforms.uGrainIntensity, red ? 0.025 : 0.04);
  gl.uniform1f(uniforms.uDirection, 0);
  gl.uniform1f(uniforms.uMouseEnabled, red ? 0 : 1);
  gl.uniform1f(uniforms.uMouseRadius, 0.5);
  gl.uniform1f(uniforms.uMouseStrength, 0.45);
  gl.uniform1f(uniforms.uMouseActive, 0);
  gl.uniform2f(uniforms.uMouse, 0.5, 0.5);
  gl.uniform3fv(uniforms.uColor1, hex(red ? "#3a0806" : "#9a3e10"));
  gl.uniform3fv(uniforms.uColor2, hex(red ? "#d42214" : "#ff6a1a"));
  gl.uniform3fv(uniforms.uColor3, hex(red ? "#6a1008" : "#c6f54a"));

  container.appendChild(canvas);
  stage.classList.add("has-scanner");

  const mouse = [0.5, 0.5];
  const target = [0.5, 0.5];
  let mouseActive = 0;
  let targetActive = 0;

  function setSize() {
    const rect = container.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const width = Math.max(1, Math.floor(rect.width));
    const height = Math.max(1, Math.floor(rect.height));
    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    gl.viewport(0, 0, canvas.width, canvas.height);
    gl.uniform2f(uniforms.iResolution, canvas.width, canvas.height);
  }

  const resize = new ResizeObserver(setSize);
  resize.observe(container);
  setSize();

  function onMove(event) {
    const rect = container.getBoundingClientRect();
    target[0] = (event.clientX - rect.left) / rect.width;
    target[1] = 1 - (event.clientY - rect.top) / rect.height;
    targetActive = 1;
  }
  function onLeave() {
    targetActive = 0;
  }
  stage.addEventListener("mousemove", onMove);
  stage.addEventListener("mouseleave", onLeave);

  let frame = 0;
  let visible = true;
  let pageVisible = !document.hidden;
  const started = performance.now();

  function draw(now) {
    gl.uniform1f(uniforms.iTime, (now - started) * 0.001);
    mouse[0] += 0.05 * (target[0] - mouse[0]);
    mouse[1] += 0.05 * (target[1] - mouse[1]);
    mouseActive += 0.05 * (targetActive - mouseActive);
    gl.uniform2f(uniforms.uMouse, mouse[0], mouse[1]);
    gl.uniform1f(uniforms.uMouseActive, mouseActive);
    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    frame = requestAnimationFrame(draw);
  }

  function start() {
    if (visible && pageVisible && frame === 0) frame = requestAnimationFrame(draw);
  }
  function stop() {
    if (frame !== 0) {
      cancelAnimationFrame(frame);
      frame = 0;
    }
  }

  const seen = new IntersectionObserver(function (entries) {
    const rect = container.getBoundingClientRect();
    const onScreen = rect.width > 1 && rect.height > 1 && rect.bottom > 0 && rect.top < window.innerHeight;
    visible = entries[0].isIntersecting || onScreen;
    if (visible) start();
    else stop();
  });
  seen.observe(container);
  document.addEventListener("visibilitychange", function () {
    pageVisible = !document.hidden;
    if (pageVisible) start();
    else stop();
  });
  start();
  });
})();
