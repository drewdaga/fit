import { Notice, arrayBufferToBase64, base64ToArrayBuffer } from "obsidian";
import { ClashStatus, FileOpRecord, LocalFileStatus, RemoteChangeType } from "./fitTypes";

type Status = RemoteChangeType | LocalFileStatus

type FileLocation = "remote" | "local"

type ComparisonResult<Env extends FileLocation> = {
    path: string, 
    status: Env extends "local" ? LocalFileStatus: RemoteChangeType
    currentSha?: string
    extension?: string
}

function getValueOrNull(obj: Record<string, string>, key: string): string | null {
    return obj.hasOwnProperty(key) ? obj[key] : null;
}


// compare currentSha with storedSha and check for differences, files only in currentSha
//  are considerd added, while files only in storedSha are considered removed
export function compareSha<Env extends "remote" | "local">(
    currentShaMap: Record<string, string>, 
    storedShaMap: Record<string, string>,
    env: Env): ComparisonResult<Env>[] {
        const determineStatus = (currentSha: string | null, storedSha: string | null): Status | null  => 
        {
            if (currentSha && storedSha && currentSha !== storedSha) {
                return env === "local" ? "changed" : "MODIFIED";
            } else if (currentSha && !storedSha) {
                return env === "local" ? "created" : "ADDED";
            } else if (!currentSha && storedSha) {
                return env === "local" ? "deleted" : "REMOVED";
            }
            return null
        }

        return Object.keys({ ...currentShaMap, ...storedShaMap }).flatMap((path): ComparisonResult<Env>[] => {
            const [currentSha, storedSha] = [getValueOrNull(currentShaMap, path), getValueOrNull(storedShaMap, path)];
            const status = determineStatus(currentSha, storedSha);
            if (status) {
                return [{
                    path,
                    status: status as Env extends "local" ? LocalFileStatus : RemoteChangeType,
                    currentSha: currentSha ?? undefined,
                    extension: extractExtension(path)
                }];
            }
            return [];
        });
}

export const RECOGNIZED_BINARY_EXT = ["png", "jpg", "jpeg", "pdf"]

export function extractExtension(path: string): string | undefined {
    return path.match(/[^.]+$/)?.[0];
}

// Using file extension to determine encoding of files (works in most cases)
export function getFileEncoding(path: string): string {
    const extension = path.match(/[^.]+$/)?.[0];
    const isBinary = extension && RECOGNIZED_BINARY_EXT.includes(extension);
    if (isBinary) {
        return "base64"
    } 
    return "utf-8"
}

export function setEqual<T>(arr1: Array<T>, arr2: Array<T>) {
    const set1 = new Set(arr1);
    const set2 = new Set(arr2);
    const isEqual = set1.size === set2.size && [...set1].every(value => set2.has(value));
    return isEqual
}

export function removeLineEndingsFromBase64String(content: string): string {
    return content.replace(/\r?\n|\r|\n/g, '');
}

// Path encryption utilities
export async function encryptPath(path: string, password: string): Promise<string> {
    const encoder = new TextEncoder();
    
    // Use deterministic salt and IV based on the path for consistency
    const pathData = encoder.encode(path);
    const hashBuffer = await crypto.subtle.digest('SHA-256', pathData);
    const salt = new Uint8Array(hashBuffer).slice(0, 16); // First 16 bytes as salt
    const iv = new Uint8Array(hashBuffer).slice(16, 28);   // Next 12 bytes as IV
    
    // Use core encryption function
    const base64 = await encryptWithKey(path, password, salt, iv);
    
    // Convert to URL-safe base64
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export async function decryptPath(encryptedPath: string, password: string): Promise<string> {
    try {
        // Convert from URL-safe base64
        const base64 = encryptedPath.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding if needed
        const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
        const encryptedData = base64ToArrayBuffer(padded);
        
        // Use core decryption function
        return await decryptWithKey(encryptedData, password);
    } catch (e) {
        // If decryption fails, return the original path
        // This handles the case of unencrypted paths
        console.log("Decryption failed, skipping...");
        return encryptedPath;
    }
}

// Core encryption utilities
async function deriveKey(password: string, salt: ArrayBuffer): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const passwordData = encoder.encode(password);

    // First create a PBKDF2 key from the password
    const baseKey = await window.crypto.subtle.importKey(
        "raw",
        passwordData,
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"]
    );

    // Then derive an AES-GCM key using PBKDF2
    return await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,  // High iteration count for security
            hash: "SHA-256"
        },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

async function encryptWithKey(
    data: string,
    password: string,
    salt: Uint8Array,
    iv: Uint8Array
): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    
    // Ensure we have proper ArrayBuffer types
    const saltBuffer = new ArrayBuffer(salt.length);
    new Uint8Array(saltBuffer).set(salt);
    
    const ivBuffer = new ArrayBuffer(iv.length);
    new Uint8Array(ivBuffer).set(iv);
    
    const key = await deriveKey(password, saltBuffer);
    
    const encryptedBuffer = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: new Uint8Array(ivBuffer) },
        key,
        dataBuffer
    );
    
    // Combine salt + IV + encrypted data
    const result = new Uint8Array(salt.length + iv.length + encryptedBuffer.byteLength);
    result.set(salt, 0);
    result.set(iv, salt.length);
    result.set(new Uint8Array(encryptedBuffer), salt.length + iv.length);
    
    return arrayBufferToBase64(result.buffer);
}

async function decryptWithKey(
    encryptedData: ArrayBuffer,
    password: string
): Promise<string> {
    // Extract salt (first 16 bytes), IV (next 12 bytes), and encrypted data (rest)
    const salt = new Uint8Array(encryptedData.slice(0, 16));
    const iv = new Uint8Array(encryptedData.slice(16, 28));
    const encrypted = encryptedData.slice(28);
    
    const key = await deriveKey(password, salt.buffer);
    
    const decryptedBuffer = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encrypted
    );
    
    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
}

// Content encryption utilities
export async function encryptContent(content: string, password: string): Promise<string> {
    // Generate random salt and IV for content encryption
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    // Use core encryption function
    return await encryptWithKey(content, password, salt, iv);
}

export async function decryptContent(encryptedContent: string, password: string): Promise<string> {
    // Convert base64 to array buffer
    const combined = base64ToArrayBuffer(encryptedContent);
    
    // Use core decryption function
    return await decryptWithKey(combined, password);
}

export function showFileOpsRecord(records: Array<{heading: string, ops: FileOpRecord[]}>): void {
    console.log(records)
    if (records.length === 0 || records.every(r=>r.ops.length===0)) {return}
    const fileOpsNotice = new Notice("", 0)
    records.map(recordSet => {
        if (recordSet.ops.length === 0) {return}
        const heading = fileOpsNotice.noticeEl.createEl("span", {
            cls: "file-changes-heading"
        })
        heading.setText(`${recordSet.heading}\n`)
        const fileChanges = {
            created: [] as Array<string>, 
            changed: [] as Array<string>, 
            deleted: [] as Array<string>
        }
        for (const op of recordSet.ops) {
            fileChanges[op.status].push(op.path)
        }
        for (const [changeType, paths] of Object.entries(fileChanges)) {
            if (paths.length === 0) {continue}
            const heading = fileOpsNotice.noticeEl.createEl("span")
            heading.setText(`${changeType.charAt(0).toUpperCase() + changeType.slice(1)}\n`)
            heading.addClass(`file-changes-subheading`)
            for (const path of paths) {
                const listItem = fileOpsNotice.noticeEl.createEl("li", {
                    cls: "file-update-row"
                });
                listItem.setText(`${path}`);
                listItem.addClass(`file-${changeType}`);
            }
        }
    })
}

export function showUnappliedConflicts(clashedFiles: Array<ClashStatus>): void {
    if (clashedFiles.length === 0) {return}
    const localStatusMap = {
        created: "create",
        changed: "change",
        deleted: "delete"
    }
    const remoteStatusMap = {
        ADDED:  "create",
        MODIFIED: "change",
        REMOVED: "delete"
    }
    const conflictNotice = new Notice("", 0)
    const heading = conflictNotice.noticeEl.createEl("span")
    heading.setText(`Change conflicts:\n`)
    heading.addClass(`file-changes-subheading`)
    const conflictStatus = conflictNotice.noticeEl.createDiv({
        cls: "file-conflict-row"
    });
    conflictStatus.createDiv().setText("Local")
	conflictStatus.createDiv().setText("Remote")
    for (const clash of clashedFiles) {
        const conflictItem = conflictNotice.noticeEl.createDiv({
            cls: "file-conflict-row"
        });
        conflictItem.createDiv({
            cls: `file-conflict-${localStatusMap[clash.localStatus]}`
        });
        conflictItem.createDiv("div")
            .setText(clash.path);
        conflictItem.createDiv({
            cls: `file-conflict-${remoteStatusMap[clash.remoteStatus]}`
        });
    }
    const footer = conflictNotice.noticeEl.createDiv({
        cls: "file-conflict-row"
    })
    footer.setText("Note:")
    footer.style.fontWeight = "bold";
    conflictNotice.noticeEl.createEl("li", {cls: "file-conflict-note"})
        .setText("Remote changes in _fit")
    conflictNotice.noticeEl.createEl("li", {cls: "file-conflict-note"})
        .setText("_fit folder is overwritten on conflict, copy needed changes outside _fit.")
}
