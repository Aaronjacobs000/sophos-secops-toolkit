// Names and device names in the scripts the PDF fonts cover, all invented, and a
// way to put them into a demo report: the person and device cells of every
// table, the users and devices charts, the directory record and the subject.

export const PEOPLE = [
  { script: "Chinese", name: "王芳" },
  { script: "Chinese (Traditional)", name: "陳美玲" },
  { script: "Japanese", name: "山田 さくら" },
  { script: "Korean", name: "김민준" },
  { script: "Thai", name: "สมชาย ใจดี" },
  { script: "Cyrillic", name: "Дмитрий Иванов" },
  { script: "Greek", name: "Γιώργος Παπαδόπουλος" },
  { script: "Arabic", name: "فاطمة الزهراء" },
  { script: "Hebrew", name: "דוד כהן" },
];

export const DEVICES = ["北京-LT-0042", "東京-LT-0007", "서울-SRV-01", "กรุงเทพ-LT-12", "МОСКВА-ПК-03", "ΑΘΗΝΑ-LT-05", "القاهرة-LT-09", "חיפה-LT-08"];

export const SUBJECT = "海港物流 (Harbourline Logistics)";
/** The user report's subject: the person it is about. */
export const USER = { name: "فاطمة الزهراء", email: "f.alzahra@harbourline.example" };

const PERSON_KEYS = new Set(["users", "user", "account", "person", "owner", "from", "to"]);
const DEVICE_KEYS = new Set(["hosts", "host", "device"]);

/** Latin letters Helvetica has no glyph for: Czech, Polish, Hungarian, Vietnamese, Romanian, Turkish, Croatian, Latvian, Lithuanian, Maltese. */
export const LATIN_EXTENDED = {
  people: ["Antonín Dvořák", "Łukasz Wróblewski", "Kőváry Zsófia", "Nguyễn Thị Thu Hằng", "Ştefan Ţăran", "Şükrü Saraçoğlu", "Đurđica Šimić", "Jānis Bērziņš", "Žydrūnė Gintautė", "Ġużeppi Ħabib"],
  devices: ["ŁÓDŹ-LT-07", "HÀ-NỘI-LT-03", "BUCUREŞTI-SRV-01", "İSTANBUL-LT-02", "BRNO-Dvořák-05"],
  subject: "Žďár Logistika s.r.o.",
  user: { name: "Nguyễn Thị Thu Hằng", email: "h.nguyen@harbourline.example" },
};

/** A copy of `doc` with non-Latin names in it, cycling through every script. */
export function withNonLatinNames(doc) {
  return withNames(doc, { people: PEOPLE.map((p) => p.name), devices: DEVICES, subject: SUBJECT, user: USER });
}

/** A copy of `doc` with the given names in its person and device cells, charts, directory record and subject. */
export function withNames(doc, names) {
  const out = structuredClone(doc);
  let p = 0;
  let d = 0;
  const person = () => names.people[p++ % names.people.length];
  const device = () => names.devices[d++ % names.devices.length];
  out.subject = doc.reportId === "user" ? `${names.user.name} (${names.user.email})` : names.subject;
  for (const s of out.sections) {
    for (const b of s.blocks) {
      if (b.kind === "table") {
        for (const row of b.rows) {
          for (const key of Object.keys(row)) {
            if (typeof row[key] !== "string" || !row[key]) continue;
            if (PERSON_KEYS.has(key)) row[key] = person();
            else if (DEVICE_KEYS.has(key)) row[key] = device();
          }
        }
      } else if (b.kind === "bars" && /users|devices/i.test(b.title)) {
        for (const row of b.rows) row.label = /users/i.test(b.title) ? person() : device();
      } else if (b.kind === "facts") {
        for (const item of b.items) if (item.label === "Name") item.value = names.user.name;
      }
    }
  }
  return out;
}
