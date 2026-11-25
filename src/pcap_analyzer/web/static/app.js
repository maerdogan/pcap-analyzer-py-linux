(function () {
  const words = JSON.parse(document.body.dataset.words || "{}");
  const t = (text) => words[text] || text;
  const secs = (v) => (v === null || v === undefined ? "–" : v < 1 ? (v * 1000).toFixed(1) + " ms" : v.toFixed(2) + " s");
  const bytes = (v) => {
    if (v === null || v === undefined) return "–";
    for (const u of ["B", "KB", "MB"]) { if (v < 1024) return (u === "B" ? v : v.toFixed(1)) + " " + u; v /= 1024; }
    return v.toFixed(1) + " GB";
  };
  const num = (field, headerName, extra) => ({ field, headerName, type: "numericColumn", width: 110, ...extra });
  const time = (field, headerName) => num(field, headerName, { valueFormatter: (p) => secs(p.value) });
  const size = (field, headerName) => num(field, headerName, { valueFormatter: (p) => bytes(p.value) });

  const GRIDS = {
    urls: (base) => ({
      columnDefs: [
        { field: "method", headerName: t("Method"), width: 95 },
        { field: "url", headerName: t("URL"), flex: 1, minWidth: 240, filter: true },
        num("requests", t("Requests")), num("failed", t("Failed"), { width: 90 }),
        time("avg_total", t("Average")), time("p95_total", t("95th pct")), time("max_total", t("Slowest")), time("avg_service", t("Service")),
        { headerName: t("Status"), width: 170, valueGetter: (p) => p.data.statuses.map((s) => (s.status || t("none")) + " ×" + s.requests).join(", ") },
      ],
      onRowClicked: (e) => { location.href = base + "/inspect?url=" + encodeURIComponent(e.data.url.split("{id}")[0]); },
    }),
    connections: (base) => ({
      columnDefs: [
        num("stream", "#", { width: 80, filter: "agNumberColumnFilter" }),
        num("start_time", t("Start"), { width: 110, valueFormatter: (p) => (p.value ? new Date(p.value * 1000).toLocaleTimeString() : "–") }),
        { headerName: t("Client"), width: 175, filter: true, valueGetter: (p) => p.data.client_ip + ":" + p.data.client_port },
        { headerName: t("Server"), width: 175, filter: true, valueGetter: (p) => p.data.server_ip + ":" + p.data.server_port },
        { field: "kind", headerName: t("Type"), width: 95, filter: true },
        { field: "sni", headerName: t("Server name"), width: 170, filter: true },
        num("packets", t("Packets"), { width: 100 }), size("bytes", t("Bytes")),
        num("requests", t("Requests"), { width: 100 }), time("avg_total", t("Average")), time("max_total", t("Slowest")), time("duration", t("Open for")),
        time("rtt_server", t("Round trip")), num("retransmissions", t("Retrans."), { width: 95 }), { field: "close_type", headerName: t("Closed"), width: 90 },
      ],
      onRowClicked: (e) => { location.href = base + "/conn/" + e.data.stream; },
    }),
    hosts: () => ({
      columnDefs: [
        { field: "host", headerName: t("Host"), flex: 1, minWidth: 220, filter: true },
        num("connections", t("Connections"), { width: 125 }), num("requests", t("Requests")), size("bytes", t("Bytes")),
        { headerName: t("Addresses"), flex: 1, valueGetter: (p) => (p.data.addresses || []).join(", ") },
      ],
    }),
  };

  function setupGrids(root) {
    root.querySelectorAll("[data-grid]").forEach(async (el) => {
      if (el.dataset.ready) return;
      el.dataset.ready = "1";
      const opts = GRIDS[el.dataset.grid](el.dataset.base);
      const rows = await (await fetch(el.dataset.src)).json();
      agGrid.createGrid(el, { ...opts, rowData: rows, defaultColDef: { sortable: true, resizable: true }, suppressCellFocus: true, rowHeight: 34, headerHeight: 36,
        rowClass: opts.onRowClicked ? "clickable" : undefined, domLayout: "normal" });
    });
  }

  const INK = "#121d33", MUTED = "#475570", LINE = "#d0d9e5", BRAND = "#1857c2", GOOD = "#08703a", BAD = "#c41d2a";
  function download(url, name) {
    Object.assign(document.createElement("a"), { href: url, download: name }).click();
  }
  function saveSvg(option, name, el) {
    const c = echarts.init(null, null, { renderer: "svg", ssr: true, width: el.clientWidth, height: el.clientHeight });
    c.setOption(option);
    const url = URL.createObjectURL(new Blob([c.renderToSVGString()], { type: "image/svg+xml" }));
    download(url, name + ".svg");
    URL.revokeObjectURL(url);
    c.dispose();
  }
  function chartButtons(el, chart, option) {
    const bar = document.createElement("p");
    bar.className = "chart-actions";
    const add = (label, onClick) => {
      const b = Object.assign(document.createElement("button"), { type: "button", textContent: label, className: "link" });
      b.addEventListener("click", onClick);
      bar.append(b);
    };
    add(t("Save as PNG"), () => download(chart.getDataURL({ type: "png", pixelRatio: 2, backgroundColor: "#ffffff" }), el.dataset.name + ".png"));
    add(t("Save as SVG"), () => saveSvg(option, el.dataset.name, el));
    el.after(bar);
  }
  const clock = (v) => new Date(v * 1000).toLocaleTimeString();
  const CHARTS = {
    timeline: (data) => {
      const times = data.rows.map((d) => clock(d.start));
      const line = (name, key, yAxisIndex, color) => ({ name, type: "line", yAxisIndex, showSymbol: false, data: data.rows.map((d) => d[key]), lineStyle: { color, width: 1.5 }, itemStyle: { color } });
      return {
        grid: { left: 48, right: 56, top: 34, bottom: 62 }, legend: { top: 0, icon: "roundRect", itemWidth: 12, itemHeight: 8 }, tooltip: { trigger: "axis" },
        dataZoom: [{ type: "slider", height: 18, bottom: 6 }],
        brush: { toolbox: ["lineX"], xAxisIndex: 0, brushMode: "single" },
        toolbox: { show: false },
        xAxis: { type: "category", data: times, axisLabel: { color: MUTED }, axisLine: { onZero: false, lineStyle: { color: LINE } } },
        yAxis: [{ type: "value", minInterval: 1, axisLabel: { color: MUTED, formatter: (v) => Math.abs(v) }, splitLine: { lineStyle: { color: LINE } } },
          { type: "value", axisLabel: { color: MUTED, formatter: (v) => secs(v) }, splitLine: { show: false } }],
        series: [
          // Errors hang below the axis, so a bad minute stands out against the traffic above it.
          { name: t("Requests"), type: "bar", data: data.rows.map((d) => d.requests), itemStyle: { color: BRAND, borderRadius: [3, 3, 0, 0] } },
          { name: t("Errors"), type: "bar", barGap: "-100%", data: data.rows.map((d) => -d.errors), itemStyle: { color: BAD, borderRadius: [0, 0, 3, 3] }, tooltip: { valueFormatter: (v) => Math.abs(v) } },
          line(t("Retransmissions"), "retransmissions", 0, "#a8489f"), line(t("Open connections"), "open_connections", 0, "#3e9b5f"),
          { ...line(t("95th percentile"), "p95_total", 1, "#e2702a"), connectNulls: false },
        ],
      };
    },
    histogram: (data) => ({
      grid: { left: 44, right: 12, top: 30, bottom: 56 }, tooltip: {},
      xAxis: { type: "category", data: data.map((d) => d.label), axisLabel: { rotate: 40, color: MUTED }, axisLine: { lineStyle: { color: LINE } } },
      yAxis: { type: "value", minInterval: 1, axisLabel: { color: MUTED }, splitLine: { lineStyle: { color: LINE } } },
      series: [{ type: "bar", data: data.map((d) => d.requests), itemStyle: { color: BRAND, borderRadius: [3, 3, 0, 0] }, barCategoryGap: "12%" }],
    }),
    statuses: (data) => ({
      grid: { left: 50, right: 12, top: 30, bottom: 28 }, tooltip: {},
      xAxis: { type: "value", minInterval: 1, axisLabel: { color: MUTED }, splitLine: { lineStyle: { color: LINE } } },
      yAxis: { type: "category", inverse: true, data: data.map((d) => d.class), axisLabel: { color: INK } },
      series: [{ type: "bar", data: data.map((d) => ({ value: d.requests,
        itemStyle: { color: /^[45]|none/.test(d.class) ? BAD : GOOD, borderRadius: [0, 3, 3, 0] } })) }],
    }),
  };

  const PHASE_COLORS = { connect_time: "#7b93ab", tls_time: "#7e6bc4", request_clean: "#1f9e8f", network: "#2f7fd1", queue_time: "#e0a82e", service: "#e2702a",
    transfer_clean: "#3e9b5f", retrans_time: "#c8324a", zero_window_time: "#a8489f", h2_flow_time: "#4a6fa5", delayed_ack_time: "#96764a" };
  CHARTS.waterfall = (data) => ({
    grid: { left: 200, right: 16, top: 34, bottom: 28 }, legend: { top: 0, type: "scroll", icon: "roundRect", itemWidth: 12, itemHeight: 8 }, tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    xAxis: { type: "value", axisLabel: { color: MUTED, formatter: (v) => secs(v) }, splitLine: { lineStyle: { color: LINE } } },
    yAxis: { type: "category", inverse: true, data: data.rows.map((d) => d.label), axisLabel: { color: INK, width: 186, overflow: "truncate" } },
    series: [{ type: "bar", stack: "t", silent: true, itemStyle: { color: "transparent" }, data: data.rows.map((d) => d.start), tooltip: { show: false } }].concat(
      Object.keys(data.phases).map((p) => ({ name: data.phases[p], type: "bar", stack: "t", itemStyle: { color: PHASE_COLORS[p] }, data: data.rows.map((d) => d[p]), tooltip: { valueFormatter: secs } }))),
  });

  const bits = (v) => {
    for (const u of ["bit/s", "kbit/s", "Mbit/s"]) { if (v < 1000) return v.toFixed(u === "bit/s" ? 0 : 1) + " " + u; v /= 1000; }
    return v.toFixed(1) + " Gbit/s";
  };
  CHARTS.io = (data) => ({
    grid: { left: 56, right: 70, top: 34, bottom: 56 }, legend: { top: 0, icon: "roundRect", itemWidth: 12, itemHeight: 8 }, tooltip: { trigger: "axis" },
    dataZoom: [{ type: "slider", height: 18, bottom: 6 }],
    xAxis: { type: "category", data: data.rows.map((d) => d.t.toFixed(3) + " s"), axisLabel: { color: MUTED }, axisLine: { lineStyle: { color: LINE } } },
    yAxis: [{ type: "value", minInterval: 1, axisLabel: { color: MUTED }, splitLine: { lineStyle: { color: LINE } } },
      { type: "value", axisLabel: { color: MUTED, formatter: bits }, splitLine: { show: false } }],
    series: [
      { name: t("Packets") + " / " + data.step + " s", type: "bar", data: data.rows.map((d) => d.packets), itemStyle: { color: BRAND } },
      { name: t("Bits per second"), type: "line", yAxisIndex: 1, showSymbol: false, data: data.rows.map((d) => d.bps), lineStyle: { color: "#e2702a", width: 1.5 },
        itemStyle: { color: "#e2702a" }, tooltip: { valueFormatter: bits } },
    ],
  });
  const SIDE_COLORS = ["#1857c2", "#3e9b5f"];
  CHARTS.tcpgraph = (data, el) => {
    const kind = el.dataset.kind;
    const axis = { stevens: t("Sequence number"), throughput: t("Bits per second"), rtt: t("Round trip"), window: t("Window") }[kind];
    const series = [];
    data.sides.forEach((s, i) => {
      const name = s.side + (s.client ? " (" + t("Client") + ")" : "");
      const color = SIDE_COLORS[i % 2];
      if (kind === "stevens") {
        series.push({ name, type: "scatter", symbolSize: 4, data: s.stevens.map((p) => [p[0], p[1]]),
          itemStyle: { color: (p) => (s.stevens[p.dataIndex][2] ? BAD : color) } });
      } else if (kind === "throughput") {
        series.push({ name, type: "line", step: "end", showSymbol: false, data: s.throughput.rows, lineStyle: { color }, itemStyle: { color } });
      } else {
        series.push({ name, type: kind === "rtt" ? "scatter" : "line", symbolSize: 4, showSymbol: kind === "rtt", data: s[kind], lineStyle: { color }, itemStyle: { color } });
      }
    });
    const fmt = kind === "throughput" ? bits : kind === "rtt" ? secs : (v) => v;
    return {
      grid: { left: 80, right: 16, top: 34, bottom: 56 }, legend: { top: 0, icon: "roundRect", itemWidth: 12, itemHeight: 8 },
      tooltip: { trigger: kind === "throughput" || kind === "window" ? "axis" : "item", valueFormatter: fmt },
      dataZoom: [{ type: "slider", height: 18, bottom: 6 }, { type: "inside" }],
      xAxis: { type: "value", name: t("Seconds"), nameLocation: "middle", nameGap: 26, axisLabel: { color: MUTED }, splitLine: { lineStyle: { color: LINE } } },
      yAxis: { type: "value", name: axis, scale: kind === "stevens", axisLabel: { color: MUTED, formatter: fmt }, splitLine: { lineStyle: { color: LINE } } },
      series,
    };
  };

  function rangeLink(el, chart, data) {
    const link = Object.assign(document.createElement("a"), { className: "button", hidden: true, textContent: t("Inspect this period") });
    el.parentElement.append(link);
    chart.dispatchAction({ type: "takeGlobalCursor", key: "brush", brushOption: { brushType: "lineX", brushMode: "single" } });
    chart.on("brushEnd", (e) => {
      const area = e.areas[0];
      link.hidden = !area;
      if (!area) return;
      const [first, last] = area.coordRange.map((i) => Math.min(Math.max(i, 0), data.rows.length - 1));
      link.href = `${el.dataset.base}/inspect?start=${data.rows[first].start}&end=${data.rows[last].start + data.width}`;
    });
  }

  function setupCharts(root) {
    root.querySelectorAll("[data-chart]").forEach(async (el) => {
      if (el.dataset.ready) return;
      el.dataset.ready = "1";
      const reply = await fetch(el.dataset.src);
      const data = await reply.json();
      if (!reply.ok) {
        el.replaceWith(Object.assign(document.createElement("p"), { className: "error", role: "alert", textContent: data.detail || reply.statusText }));
        return;
      }
      const chart = echarts.init(el, null, { renderer: "canvas" });
      const make = () => ({ textStyle: { fontFamily: "Archivo, system-ui, sans-serif" }, animation: false, ...CHARTS[el.dataset.chart](data, el) });
      let option = make();
      chart.setOption(option);
      chartButtons(el, chart, option);
      if (el.dataset.chart === "timeline") rangeLink(el, chart, data);
      el.closest(".panel")?.querySelectorAll("[data-graph-switch] a").forEach((a) => a.addEventListener("click", (e) => {
        e.preventDefault();
        el.dataset.kind = a.dataset.kind;
        a.parentElement.querySelectorAll("a").forEach((b) => b.toggleAttribute("aria-current", b === a));
        option = make();
        chart.setOption(option, true);
      }));
      addEventListener("resize", () => chart.resize());
    });
  }

  // One URL over time on the inspect page: phases stacked per time bucket, the 95th percentile as a dashed line, and requests and
  // failed requests as bars below. Selecting a row of the URL table switches the chart and the table of where the time went beside it.
  function setupUrlView(root) {
    const view = root.id === "url-view" ? root : root.querySelector("#url-view");
    if (!view || !view.dataset.urlData || view.dataset.ready || typeof echarts === "undefined") return;
    view.dataset.ready = "1";
    const all = JSON.parse(view.dataset.urlData);
    const chart = echarts.init(view.querySelector("[data-url-chart]"), null, { renderer: "canvas" });
    const count = (v) => (typeof v === "number" && v % 1 === 0 && v > 1 ? v : secs(v));
    const draw = (i) => {
      const u = all.urls[i], pts = u.series || [];
      const used = Object.keys(all.labels).filter((p) => pts.some((d) => d.phases && d.phases[p] > 0));
      const x = (d) => d.t * 1000;
      chart.setOption({
        animation: false, textStyle: { fontFamily: "Archivo, system-ui, sans-serif" },
        grid: [{ left: 64, right: 16, top: 36, height: "58%" }, { left: 64, right: 16, top: "76%", bottom: 46 }],
        legend: { top: 0, type: "scroll", icon: "roundRect", itemWidth: 12, itemHeight: 8 },
        tooltip: { trigger: "axis", axisPointer: { type: "cross" }, valueFormatter: count },
        axisPointer: { link: [{ xAxisIndex: "all" }] },
        dataZoom: [{ type: "inside", xAxisIndex: [0, 1] }, { type: "slider", xAxisIndex: [0, 1], height: 16, bottom: 6 }],
        xAxis: [{ type: "time", gridIndex: 0, axisLabel: { show: false }, axisLine: { lineStyle: { color: LINE } } },
          { type: "time", gridIndex: 1, axisLabel: { color: MUTED }, axisLine: { lineStyle: { color: LINE } } }],
        yAxis: [{ type: "value", gridIndex: 0, axisLabel: { color: MUTED, formatter: secs }, splitLine: { lineStyle: { color: LINE } } },
          { type: "value", gridIndex: 1, minInterval: 1, axisLabel: { color: MUTED }, splitLine: { show: false }, name: t("Requests"), nameTextStyle: { color: MUTED, align: "left" } }],
        series: [
          ...used.map((p) => ({ name: all.labels[p], type: "line", stack: "phases", areaStyle: { opacity: 0.85 }, symbol: "none", lineStyle: { width: 0 },
            itemStyle: { color: PHASE_COLORS[p] }, data: pts.map((d) => [x(d), d.phases[p] || 0]) })),
          { name: t("95th percentile"), type: "line", symbol: "none", lineStyle: { color: INK, width: 1.5, type: "dashed" }, itemStyle: { color: INK }, data: pts.map((d) => [x(d), d.p95]) },
          { name: t("Requests"), type: "bar", xAxisIndex: 1, yAxisIndex: 1, itemStyle: { color: BRAND }, data: pts.map((d) => [x(d), d.n]) },
          { name: t("Failed"), type: "bar", xAxisIndex: 1, yAxisIndex: 1, barGap: "-100%", itemStyle: { color: BAD }, data: pts.map((d) => [x(d), d.failed]) },
        ],
      }, true);
      view.querySelector("[data-url-title]").textContent = u.title;
      view.querySelectorAll("[data-url-table]").forEach((el) => { el.hidden = el.dataset.urlTable !== String(i); });
      document.querySelectorAll("tr[data-url-pick]").forEach((r) => r.classList.toggle("picked", r.dataset.urlPick === String(i)));
    };
    draw(0);
    document.querySelectorAll("tr[data-url-pick]").forEach((r) => {
      const pick = () => { draw(Number(r.dataset.urlPick)); view.scrollIntoView({ behavior: "smooth", block: "nearest" }); };
      r.addEventListener("click", pick);
      r.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    });
    addEventListener("resize", () => chart.resize());
  }

  // Plain tables marked data-sortable: a column title sorts by that column, and again in the other direction.
  // Cells may carry data-value, the raw number behind a formatted value such as "1.2 s".
  function setupSorting(root) {
    root.querySelectorAll("table[data-sortable]").forEach((table) => {
      if (table.dataset.ready) return;
      table.dataset.ready = "1";
      table.querySelectorAll("th[data-sort]").forEach((th, col) => {
        th.tabIndex = 0;
        th.classList.add("sortable");
        const sort = () => {
          const down = th.getAttribute("aria-sort") !== "descending";
          table.querySelectorAll("th[aria-sort]").forEach((o) => o.removeAttribute("aria-sort"));
          th.setAttribute("aria-sort", down ? "descending" : "ascending");
          const key = (row) => {
            const cell = row.cells[col];
            if (th.dataset.sort === "num") return parseFloat(cell.dataset.value ?? cell.textContent) || 0;
            return cell.textContent.trim().toLowerCase();
          };
          const body = table.tBodies[0];
          [...body.rows].sort((a, b) => {
            const x = key(a), y = key(b);
            return (x < y ? -1 : x > y ? 1 : 0) * (down ? -1 : 1);
          }).forEach((row) => body.append(row));
        };
        th.addEventListener("click", sort);
        th.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); sort(); } });
      });
    });
  }

  function setup(root) {
    setupSorting(root);
    setupGrids(root);
    setupCharts(root);
    setupUrlView(root);
    root.querySelectorAll("[data-submit]").forEach((el) => el.addEventListener("change", () => el.form.submit()));
    // A most called flow fills the inspect filter with its two ends and runs it; other fields are cleared so the flow alone decides.
    root.querySelectorAll(".flow-pick").forEach((b) => b.addEventListener("click", () => {
      const form = document.getElementById("f");
      if (!form) return;
      const set = (name, value) => { const el = form.elements[name]; if (el) el.value = value; };
      ["url", "min_size", "kind"].forEach((n) => set(n, ""));
      set("src", b.dataset.src); set("src_port", b.dataset.srcPort); set("dst", b.dataset.dst); set("port", b.dataset.port);
      document.querySelectorAll(".flow-pick").forEach((o) => o.toggleAttribute("aria-current", o === b));
      form.requestSubmit();
    }));
  }
  // On narrow screens the side menu slides in over the page.
  function setupSideMenu() {
    const toggle = document.querySelector("[data-nav-toggle]"), scrim = document.querySelector("[data-nav-close]");
    if (!toggle) return;
    const show = (open) => {
      document.body.classList.toggle("nav-open", open);
      toggle.setAttribute("aria-expanded", String(open));
      scrim.hidden = !open;
    };
    toggle.addEventListener("click", () => show(!document.body.classList.contains("nav-open")));
    scrim.addEventListener("click", () => show(false));
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && document.body.classList.contains("nav-open")) { show(false); toggle.focus(); } });
  }
  document.addEventListener("DOMContentLoaded", () => {
    setup(document);
    document.body.addEventListener("htmx:afterSettle", (e) => setup(e.target));
    setupSideMenu();
  });
})();
