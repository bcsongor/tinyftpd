// Makes the file list nicer to use. Without it every action still works
// through plain forms and small pages asking for names or confirmation.
"use strict";

// Set before the page draws, so the CSS can swap in the JavaScript controls
// without a flash.
document.documentElement.classList.add("js");

addEventListener("DOMContentLoaded", () => {
  const items = document.getElementById("items");
  if (items) selection(items);
  const upload = document.getElementById("upload");
  if (upload) uploads(upload);

  const note = sessionStorage.getItem("note");
  if (note) {
    sessionStorage.removeItem("note");
    status(note);
  }
});

// status shows a line above the list. kind "error" makes it red.
function status(text, kind = "") {
  const box = document.getElementById("status");
  if (!box) return null;
  box.hidden = false;
  box.className = "status " + kind;
  box.querySelector(".text").textContent = text;
  box.querySelector(".meter").hidden = true;
  box.querySelector(".pct").textContent = "";
  return box;
}

// selection: tick rows to act on them. Clicking a name opens it; clicking
// anywhere else on the row ticks it. Shift-click ticks a range, Esc clears.
function selection(form) {
  const boxes = [...form.querySelectorAll("tbody input[name=name]")];
  const all = document.getElementById("all");
  const button = (action) => document.querySelector(`button[data-action=${action}]`);
  const [download, rename, del] = ["download", "rename", "delete"].map(button);
  const selectedNote = document.getElementById("selected");
  let last = null;

  const chosen = () => boxes.filter((b) => b.checked);
  const update = () => {
    const ticked = chosen();
    const n = ticked.length;
    for (const b of boxes) b.closest("tr").classList.toggle("selected", b.checked);
    if (download) download.disabled = !(n === 1 && ticked[0].hasAttribute("data-file"));
    if (rename) rename.disabled = n !== 1;
    if (del) {
      del.disabled = n === 0;
      del.querySelector(".label").textContent = n > 1 ? `Delete (${n})` : "Delete";
    }
    if (selectedNote) selectedNote.textContent = n ? ` ${n} selected.` : "";
    if (all) {
      all.checked = n > 0 && n === boxes.length;
      all.indeterminate = n > 0 && n < boxes.length;
    }
  };
  const ticked = (box, e) => {
    if (e.shiftKey && last && last !== box) {
      const [from, to] = [boxes.indexOf(last), boxes.indexOf(box)].sort((a, b) => a - b);
      for (let i = from; i <= to; i++) boxes[i].checked = box.checked;
    }
    last = box;
    update();
  };

  for (const box of boxes) box.addEventListener("click", (e) => ticked(box, e));
  const body = form.querySelector("tbody");
  body?.addEventListener("click", (e) => {
    if (e.target.closest("a, input")) return;
    const box = e.target.closest("tr")?.querySelector("input[name=name]");
    if (!box) return;
    box.checked = !box.checked;
    ticked(box, e);
  });
  // Shift-clicking rows would otherwise select their text.
  body?.addEventListener("mousedown", (e) => {
    if (e.shiftKey && !e.target.closest("a, input")) e.preventDefault();
  });
  all?.addEventListener("change", () => {
    for (const b of boxes) b.checked = all.checked;
    last = null;
    update();
  });
  addEventListener("keydown", (e) => {
    if (e.key === "Escape" && chosen().length) {
      for (const b of boxes) b.checked = false;
      update();
    }
  });

  // Ask with the browser's own dialogs, and send the answer with the form.
  form.addEventListener("submit", (e) => {
    const names = chosen().map((b) => b.value);
    const questions = {
      delete: () =>
        confirm(names.length === 1 ? `Delete "${names[0]}"?` : `Delete these ${names.length} items?`) && {
          confirm: "1",
        },
      rename: () => {
        const to = prompt(`Rename "${names[0]}" to:`, names[0])?.trim();
        return to && to !== names[0] && { to };
      },
      mkdir: () => {
        const folder = prompt("Name of the new folder:")?.trim();
        return folder && { folder };
      },
    };
    const ask = questions[e.submitter?.dataset.action];
    if (!ask) return;
    const answer = ask();
    if (!answer) {
      e.preventDefault();
      return;
    }
    for (const [name, value] of Object.entries(answer)) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = value;
      form.append(input);
    }
  });

  update();
}

// uploads: pick files or drop them anywhere, and watch the progress.
function uploads(form) {
  const input = form.querySelector("input[type=file]");
  form.querySelector("[data-pick]").addEventListener("click", () => input.click());
  input.addEventListener("change", () => send(input.files));

  let depth = 0; // dragenter and dragleave fire for every child element
  const dragging = (e) => e.dataTransfer?.types.includes("Files");
  addEventListener("dragenter", (e) => {
    if (!dragging(e)) return;
    depth++;
    document.body.classList.add("dropping");
  });
  addEventListener("dragleave", (e) => {
    if (!dragging(e) || --depth > 0) return;
    depth = 0;
    document.body.classList.remove("dropping");
  });
  addEventListener("dragover", (e) => {
    if (dragging(e)) e.preventDefault();
  });
  addEventListener("drop", (e) => {
    if (!dragging(e)) return;
    e.preventDefault();
    depth = 0;
    document.body.classList.remove("dropping");
    send(e.dataTransfer.files);
  });

  let busy = false;
  addEventListener("beforeunload", (e) => {
    if (busy) e.preventDefault(); // leaving would cancel the upload
  });

  function send(files) {
    if (!files.length || busy) return;
    busy = true;
    const what = files.length === 1 ? files[0].name : `${files.length} files`;
    const box = status(`Uploading ${what}…`);
    const meter = box.querySelector(".meter");
    const pct = box.querySelector(".pct");
    meter.hidden = false;

    const data = new FormData();
    for (const f of files) data.append("file", f);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", form.action);
    xhr.upload.addEventListener("progress", (e) => {
      if (!e.lengthComputable) return;
      const done = Math.round((100 * e.loaded) / e.total);
      meter.firstElementChild.style.width = done + "%";
      pct.textContent = done + "%";
    });
    xhr.addEventListener("load", () => {
      if (xhr.status < 400) {
        busy = false;
        sessionStorage.setItem("note", `Uploaded ${what}.`);
        location.reload();
        return;
      }
      // The server explains failures on a small page; show its reason.
      const page = new DOMParser().parseFromString(xhr.responseText, "text/html");
      failed(page.querySelector(".ask p")?.textContent || `the server said ${xhr.status}`);
    });
    xhr.addEventListener("error", () => failed("the connection dropped"));
    xhr.send(data);

    function failed(why) {
      busy = false;
      input.value = "";
      status(`Couldn't upload ${what}: ${why}.`, "error");
    }
  }
}
