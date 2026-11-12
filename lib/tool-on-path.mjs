// A tool that could not be started with ENOENT is one of two things, and the error does not say
// which: nothing on PATH has that name, or something has and the system could not start it. The
// second is an install that broke: a script whose #! line names an interpreter that is gone (a
// pipx or venv install after its Python was upgraded or removed), or a link whose target is gone.
// Reading both as "not installed" tells the reader to install what they have, and for a tool that is
// optional it says nothing at all.
//
// Nothing here starts a process: the difference is read from PATH and from the file.
import { closeSync, existsSync, lstatSync, openSync, readlinkSync, readSync, statSync } from "fs";
import path from "path";

/** The first entry on PATH with this name, or null. A link whose target is gone is an entry. */
export function entryOnPath(name, env = process.env) {
  for (const dir of (env.PATH || "").split(path.delimiter)) {
    if (!dir) continue;
    const file = path.join(dir, name);
    try {
      if (!lstatSync(file).isDirectory()) return file;
    } catch {
      // Not in this directory, or the directory is not one. A directory that cannot be searched is
      // EACCES from the start itself, so the caller is not here with ENOENT because of it.
    }
  }
  return null;
}

/** The first line of a file when it is a #! line: the interpreter it names. Null when it is not one, or unread. */
function interpreterOf(file) {
  let fd;
  try {
    fd = openSync(file, "r");
    const buf = Buffer.alloc(512);
    const head = buf.toString("latin1", 0, readSync(fd, buf, 0, buf.length, 0));
    const m = head.match(/^#![ \t]*([^ \t\r\n]+)/);
    return m ? m[1] : null;
  } catch {
    return null;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * For a tool whose start failed with ENOENT: null when nothing on PATH has its name (it is not
 * installed), otherwise a clause saying what is there and, where the file shows it, why it did not
 * start. The clause goes inside the caller's did-not-run message.
 */
export function presentNotStarted(name, env = process.env) {
  const file = entryOnPath(name, env);
  if (!file) return null;
  let why = "the system could not start it (ENOENT)";
  try {
    statSync(file);
    const interpreter = interpreterOf(file);
    if (interpreter && !existsSync(interpreter)) why = `its #! line names ${interpreter}, which does not exist`;
  } catch {
    let target = null;
    try {
      target = readlinkSync(file);
    } catch {
      // Not a link, or unreadable: the general reason stands.
    }
    if (target) why = `it is a link to ${target}, which does not exist`;
  }
  return `${file} is on PATH and could not be started: ${why}`;
}
