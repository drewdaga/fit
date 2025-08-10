import { TFile, Vault, base64ToArrayBuffer, arrayBufferToBase64 } from "obsidian";
import { FileOpRecord } from "./fitTypes";
import { encryptContent, decryptContent } from "./utils";


export interface IVaultOperations {
    vault: Vault
    deleteFromLocal: (path: string) => Promise<FileOpRecord>
    writeToLocal: (path: string, content: string) => Promise<FileOpRecord>
    updateLocalFiles: (
        addToLocal: {path: string, content: string}[], deleteFromLocal: Array<string>) 
        => Promise<FileOpRecord[]>
    createCopyInDir: (path: string, copyDir: string) => Promise<void>
}

export class VaultOperations implements IVaultOperations {
    vault: Vault
    settings: {enableEncryption: boolean, password: string}

    constructor(vault: Vault, settings: {enableEncryption: boolean, password: string}) {
        this.vault = vault
        this.settings = settings
    }

    async getTFile(path: string): Promise<TFile> {
        const file = this.vault.getAbstractFileByPath(path)
        if (file && file instanceof TFile) {
            return file
        } else {
            throw new Error(`Attempting to read ${path} from local drive as TFile but not successful,
            file is of type ${typeof file}.`)
        }
    }

    async deleteFromLocal(path: string): Promise<FileOpRecord> {
        // adopted getAbstractFileByPath for mobile compatiability
        const file = this.vault.getAbstractFileByPath(path)
        if (file && file instanceof TFile) {
            await this.vault.delete(file);
            return {path, status: "deleted"}
        } 
        throw new Error(`Attempting to delete ${path} from local but not successful, file is of type ${typeof file}.`);
    }

    // if checking a folder, require including the last / in the path param
    async ensureFolderExists(path: string): Promise<void> {
        // extract folder path, return empty string is no folder path is matched (exclude the last /)
        const folderPath = path.match(/^(.*)\//)?.[1] || '';
        if (folderPath != "") {
            const folder = this.vault.getAbstractFileByPath(folderPath)
            if (!folder) {
                await this.vault.createFolder(folderPath)
            }
        }
    }

    async writeToLocal(path: string, content: string): Promise<FileOpRecord> {
        // Decrypt content if encryption is enabled
        let dataToWrite: string;
        if (this.settings.enableEncryption) {
            try {
                dataToWrite = await decryptContent(content, this.settings.password);
            } catch (e) {
                // If decryption fails, try using content directly as it might be unencrypted
                dataToWrite = content;
            }
        } else {
            dataToWrite = content;
        }

        const file = this.vault.getAbstractFileByPath(path);
        if (file && file instanceof TFile) {
            await this.vault.modifyBinary(file, base64ToArrayBuffer(dataToWrite));
            return {path, status: "changed"};
        } else if (!file) {
            this.ensureFolderExists(path);
            await this.vault.createBinary(path, base64ToArrayBuffer(dataToWrite));
            return {path, status: "created"};
        } 
        throw new Error(`${path} writeToLocal operation unsuccessful, vault abstractFile on ${path} is of type ${typeof file}`);
    }

    async updateLocalFiles(
        addToLocal: {path: string, content: string}[], 
        deleteFromLocal: Array<string>): Promise<FileOpRecord[]> {
            // Process file additions or updates
            const writeOperations = addToLocal.map(async ({path, content}) => {
                return await this.writeToLocal(path, content)
            });
        
            // Process file deletions
            const deletionOperations = deleteFromLocal.map(async (path) => {
                return await this.deleteFromLocal(path)
            });
            const fileOps = await Promise.all([...writeOperations, ...deletionOperations]);
            return fileOps
    }

    async readAndEncryptContent(file: TFile): Promise<string> {
        const content = arrayBufferToBase64(await this.vault.readBinary(file));
        if (this.settings.enableEncryption) {
            return await encryptContent(content, this.settings.password);
        }
        return content;
    }

    async createCopyInDir(path: string, copyDir = "_fit"): Promise<void> {
        const file = this.vault.getAbstractFileByPath(path)
        if (file && file instanceof TFile) {
            const copy = await this.vault.readBinary(file)
            const copyPath = `${copyDir}/${path}`
            this.ensureFolderExists(copyPath)
            const copyFile = this.vault.getAbstractFileByPath(path)
            if (copyFile && copyFile instanceof TFile) {
                await this.vault.modifyBinary(copyFile, copy)
            } else if (!copyFile) {
                await this.vault.createBinary(copyPath, copy)
            } else {
                this.vault.delete(copyFile, true) // TODO add warning to let user know files in _fit will be overwritten
                await this.vault.createBinary(copyPath, copy)
            }
            await this.vault.createBinary(copyPath, copy)
        } else {
            throw new Error(`Attempting to create copy of ${path} from local drive as TFile but not successful,
            file is of type ${typeof file}.`)
        }
    }
}