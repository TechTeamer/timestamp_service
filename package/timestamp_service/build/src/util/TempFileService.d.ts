import tmp from 'tmp';
export declare class TempFileService {
    /**
     * Utility to create a temp file with content
     * */
    createTempFile(options: tmp.FileOptions, content?: Buffer): Promise<{
        tempPath: string;
        fd: number | undefined;
        cleanupCallback: () => void;
    }>;
}
