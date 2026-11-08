// Schema Atlas: the Fusion event schemas (dated snapshot of qlSchemaMapV1)
// and the Classic Data Lake tables (docs.sophos.com), browsable and
// searchable offline in plain language.

import { h, clear, setText } from "../dom.js";
import { icon } from "../icons.js";
import { reconcile, reducedMotion } from "../anim.js";
import { num, date } from "../format.js";
import { store } from "../api.js";
import { segmented } from "./common.js";

let st = null;
const cache = {};

async function loadCatalog(which) {
  if (!cache[which]) cache[which] = fetch(`/data/atlas-${which}.json`).then((r) => r.json());
  return cache[which];
}

function normalise(which, raw) {
  if (which === "fusion") {
    return {
      which,
      source: raw.source,
      snapshot: raw.snapshot,
      version: raw.version,
      joins: raw.joins ?? {},
      logical: raw.logical ?? [],
      entities: raw.schemas.map((s) => ({
        id: s.name,
        name: s.friendly,
        tech: s.name,
        group: s.category === "EVENTS" ? "Event schemas" : s.category === "ALERTS" ? "Detections" : s.category,
        description: s.description,
        fields: s.fields.map((f) => ({ name: f.n, description: f.d, type: f.t, searchable: f.s, aggregatable: f.a, repeated: f.r, nested: f.k > 0, values: f.v ?? null, oldNames: !!f.o })),
      })),
    };
  }
  const entities = [];
  for (const g of raw.groups) {
    for (const t of g.tables) {
      entities.push({
        id: `${g.schema}:${t.name}`,
        name: t.name.replace(/_/g, " "),
        tech: t.name,
        group: g.name,
        description: t.description,
        platforms: t.platforms,
        fields: t.columns.map((c) => ({ name: c.n, description: c.d, type: c.t, searchable: null, aggregatable: null, repeated: false, nested: false, values: null, oldNames: false })),
      });
    }
  }
  return { which, source: raw.source, snapshot: raw.snapshot, version: null, joins: {}, logical: [], entities };
}

function fieldCard(f) {
  const el = h("button", { type: "button", class: "fcard" });
  fillField(el, f);
  return el;
}

function fillField(el, f) {
  clear(el);
  el.classList.toggle("on", st?.field === f.name);
  el.classList.toggle("nested", f.nested);
  el.append(
    h("span", { class: "fcard-name mono", text: f.name }),
    h("span", { class: "fcard-desc", text: f.description || "No description from Sophos." }),
    h("span", { class: "fcard-tags" }, h("i", { class: "tag tag-type", text: f.type || "?" }), f.searchable ? h("i", { class: "tag", text: "search" }) : null, f.aggregatable ? h("i", { class: "tag", text: "aggregate" }) : null, f.values ? h("i", { class: "tag", text: `${f.values.length} values` }) : null),
  );
  el.onclick = () => selectField(f.name);
}

function renderList() {
  const box = st.listBox;
  clear(box);
  const q = st.query.trim().toLowerCase();
  const groups = new Map();
  for (const e of st.cat.entities) {
    const hit = !q || e.name.toLowerCase().includes(q) || e.tech.toLowerCase().includes(q) || e.fields.some((f) => f.name.toLowerCase().includes(q) || f.description.toLowerCase().includes(q));
    if (!hit) continue;
    if (!groups.has(e.group)) groups.set(e.group, []);
    groups.get(e.group).push(e);
  }
  for (const [g, list] of groups) {
    box.append(h("h3", { class: "ent-group", text: g }));
    for (const e of list) {
      const matches = q ? e.fields.filter((f) => f.name.toLowerCase().includes(q) || f.description.toLowerCase().includes(q)).length : 0;
      box.append(
        h(
          "button",
          { type: "button", class: `ent${st.entity?.id === e.id ? " on" : ""}`, onclick: () => selectEntity(e.id) },
          h("span", { class: "ent-name" }, h("b", { text: e.name }), h("small", { class: "mono", text: e.tech })),
          h("span", { class: "ent-count", text: q && matches ? `${num(matches)} match` : `${num(e.fields.length)} fields` }),
        ),
      );
    }
  }
  if (!groups.size) box.append(h("p", { class: "dim pad", text: "Nothing matches." }));
}

function renderEntity() {
  const e = st.entity;
  const head = st.entHead;
  clear(head);
  if (!e) return;
  const searchable = e.fields.filter((f) => f.searchable).length;
  const described = e.fields.filter((f) => f.description).length;
  head.append(
    h("div", { class: "ent-title" }, h("h2", { text: e.name }), h("code", { text: e.tech })),
    h("p", { class: "ent-desc", text: e.description || "No description from Sophos." }),
    h(
      "div",
      { class: "ent-stats" },
      h("span", {}, h("b", { text: num(e.fields.length) }), " fields"),
      st.cat.which === "fusion" ? h("span", {}, h("b", { text: num(searchable) }), " searchable") : null,
      h("span", {}, h("b", { text: `${e.fields.length ? Math.round((described / e.fields.length) * 100) : 0}%` }), " described"),
      e.platforms?.length ? h("span", { text: e.platforms.join(", ") }) : null,
    ),
  );
  const q = st.query.trim().toLowerCase();
  let fields = e.fields;
  if (st.filter === "search") fields = fields.filter((f) => f.searchable);
  if (st.filter === "values") fields = fields.filter((f) => f.values);
  if (st.filter === "top") fields = fields.filter((f) => !f.nested);
  if (q) fields = [...fields].sort((a, b) => Number(b.name.toLowerCase().includes(q) || b.description.toLowerCase().includes(q)) - Number(a.name.toLowerCase().includes(q) || a.description.toLowerCase().includes(q)));
  const shown = fields.slice(0, 240);
  reconcile(st.cards, shown, (f) => `${e.id}:${f.name}`, fieldCard, fillField, { instantExit: true, duration: 400 });
  setText(st.cardsNote, fields.length > shown.length ? `Showing ${num(shown.length)} of ${num(fields.length)}. Search to narrow.` : "");
}

function renderField() {
  const box = st.detail;
  clear(box);
  const e = st.entity;
  const f = e?.fields.find((x) => x.name === st.field) ?? null;
  if (!f) {
    box.append(h("div", { class: "detail-empty" }, icon("layers", 28), h("p", { text: "Pick a field to see what it holds." })));
    renderLogical(box);
    return;
  }
  const also = (st.cat.joins[f.name] ?? []).filter((n) => n !== e.tech);
  box.append(
    h("h3", { class: "mono detail-name", text: f.name }),
    h("p", { class: "detail-desc", text: f.description || "No description from Sophos." }),
    f.oldNames ? h("p", { class: "gap-note" }, icon("info", 13), h("span", { text: "Sophos's description still uses a pre-Fusion product name." })) : null,
    h(
      "dl",
      { class: "detail-dl" },
      h("dt", { text: "Schema" }),
      h("dd", {}, h("b", { text: e.name }), " ", h("code", { text: e.tech })),
      h("dt", { text: "Type" }),
      h("dd", { text: `${f.type || "unknown"}${f.repeated ? ", repeated" : ""}${f.nested ? ", nested" : ""}` }),
      st.cat.which === "fusion" ? h("dt", { text: "Search" }) : null,
      st.cat.which === "fusion" ? h("dd", { text: `${f.searchable ? "Searchable" : "Not searchable"}, ${f.aggregatable ? "can aggregate" : "no aggregation"}` }) : null,
      h("dt", { text: st.cat.which === "fusion" ? "Query as" : "SQL" }),
      h("dd", {}, h("code", { class: "query-snippet", text: st.cat.which === "fusion" ? `FROM ${e.tech} WHERE ${f.name} = ''` : sqlFor(e, f) })),
    ),
    f.values ? h("div", { class: "detail-values" }, h("h4", { text: "Allowed values" }), h("div", { class: "chips" }, f.values.map((v) => h("span", { class: "chip mono", text: v })))) : null,
    also.length ? h("div", { class: "detail-joins" }, h("h4", { text: `Also in ${num(also.length)} other ${also.length === 1 ? "schema" : "schemas"}` }), h("p", { class: "dim", text: "A shared field is how events in different schemas line up (there is no JOIN in Fusion QL)." }), h("div", { class: "chips" }, also.slice(0, 30).map((n) => h("button", { type: "button", class: "chip chip-link", text: n, onclick: () => selectEntity(n, f.name) })))) : null,
  );
  if (!reducedMotion()) box.animate([{ opacity: 0, transform: "translateX(14px)" }, { opacity: 1, transform: "none" }], { duration: 320, easing: "cubic-bezier(.2,.75,.15,1)" });
}

const PACK_TABLE = { Endpoint: "xdr_data", Detection: "xdr_ioc_view", M365: "xdr_identity_o365" };

/** Query packs live in a shared table, picked by query_name; the rest are tables of their own. */
function sqlFor(e, f) {
  const base = PACK_TABLE[e.group];
  return base ? `SELECT ${f.name} FROM ${base} WHERE query_name = '${e.tech}'` : `SELECT ${f.name} FROM ${e.tech}`;
}

function renderLogical(box) {
  if (!st.cat.logical.length) return;
  box.append(
    h("h4", { class: "logical-head", text: "Logical types" }),
    h("p", { class: "dim small", text: "Fusion expands these across every schema that holds a field of that kind." }),
    h("div", { class: "logical" }, st.cat.logical.map((l) => h("div", { class: "logical-row" }, h("code", { text: l.name }), h("span", { text: l.description })))),
  );
}

function selectEntity(id, field = null) {
  st.entity = st.cat.entities.find((e) => e.id === id || e.tech === id) ?? st.entity;
  st.field = field;
  store.set(`atlas-${st.cat.which}`, st.entity?.id);
  renderList();
  renderEntity();
  renderField();
  if (window.innerWidth < 900) st.entHead.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", block: "start" });
}

function selectField(name) {
  st.field = name;
  for (const el of st.cards.children) el.classList.toggle("on", el.dataset.key === `${st.entity.id}:${name}`);
  renderField();
  if (window.innerWidth < 1100) st.detail.scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth", block: "nearest" });
}

async function switchCatalog(which) {
  const raw = await loadCatalog(which);
  st.cat = normalise(which, raw);
  store.set("atlas-catalog", which);
  const remembered = store.get(`atlas-${which}`, null);
  st.entity = st.cat.entities.find((e) => e.id === remembered) ?? st.cat.entities.find((e) => e.tech === "process" || e.tech === "running_processes_windows_sophos") ?? st.cat.entities[0];
  st.field = null;
  clear(st.cards);
  setText(st.meta, which === "fusion" ? `Fusion snapshot ${date(st.cat.snapshot)}, schema version ${st.cat.version}` : `Data Lake schemas from docs.sophos.com, ${date(st.cat.snapshot)}`);
  renderList();
  renderEntity();
  renderField();
}

export default {
  id: "atlas",
  async load() {
    const which = store.get("atlas-catalog", "fusion");
    await loadCatalog(which);
    return { which };
  },
  mount(root, d) {
    const wrap = h("section", { class: "atlas" });
    const search = h("input", { type: "search", placeholder: "Find a field, e.g. command line", "aria-label": "Search schemas and fields" });
    const listBox = h("div", { class: "ent-list" });
    const meta = h("p", { class: "atlas-meta dim" });
    const cats = segmented(
      [
        ["fusion", "Fusion (XDR, NG-SIEM)"],
        ["datalake", "Data Lake (Classic)"],
      ],
      d.which,
      async (v) => {
        for (const b of cats.children) b.classList.toggle("on", b.textContent.startsWith(v === "fusion" ? "Fusion" : "Data"));
        await switchCatalog(v);
      },
      "Catalogue",
    );
    const left = h("aside", { class: "atlas-left panel reveal" }, h("div", { class: "atlas-head" }, h("h2", {}, icon("layers", 16), "Catalogue")), cats, h("label", { class: "search" }, icon("search", 15), search), listBox, meta);
    const entHead = h("div", { class: "ent-head" });
    const filterSeg = segmented(
      [
        ["all", "All fields"],
        ["top", "Top level"],
        ["search", "Searchable"],
        ["values", "With values"],
      ],
      "top",
      (v) => {
        st.filter = v;
        for (const b of filterSeg.children) b.classList.toggle("on", b.dataset.v === v);
        renderEntity();
      },
      "Field filter",
    );
    [...filterSeg.children].forEach((b, i) => (b.dataset.v = ["all", "top", "search", "values"][i]));
    const cards = h("div", { class: "fcards" });
    const cardsNote = h("p", { class: "dim small" });
    const mid = h("section", { class: "atlas-mid panel reveal" }, entHead, filterSeg, cards, cardsNote);
    const detail = h("aside", { class: "atlas-right panel reveal" });
    wrap.append(
      h("div", { class: "view-head reveal" }, h("div", {}, h("h1", { text: "Schema Atlas" }), h("p", { class: "sub", text: "Every field Sophos describes, in plain language. Works offline from a dated snapshot." }))),
      h("div", { class: "atlas-grid" }, left, mid, detail),
      h("p", { class: "gap-line" }, icon("info", 13), h("span", { text: "The Fusion catalogue comes from qlSchemaMapV1, an undocumented Sophos query, captured once and shipped with the toolkit. It is reviewed when Sophos publishes Search GraphQL. The Data Lake catalogue is Sophos's public schema JSON." })),
    );
    root.append(wrap);
    st = { root, wrap, listBox, entHead, cards, cardsNote, detail, meta, query: "", filter: "top", cat: null, entity: null, field: null };
    let t = null;
    search.addEventListener("input", () => {
      clearTimeout(t);
      t = setTimeout(() => {
        st.query = search.value;
        renderList();
        renderEntity();
      }, 120);
    });
    switchCatalog(d.which);
  },
  unmount() {
    st = null;
  },
};
