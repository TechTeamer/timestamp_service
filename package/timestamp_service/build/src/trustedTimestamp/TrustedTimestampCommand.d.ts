export declare function getTsQuery(digest: string, digestFormat: string): Promise<string>;
export declare function getTsVerify(digest: string, tempPath: string, isToken: boolean, certsLocation: string): Promise<string>;
export declare function getTsReply(inputTempPath: string, isToken: boolean): Promise<string>;
export declare function generateTsReply(inputTempPath: string, tempPath: string): Promise<void>;
export declare function extractCertFromToken(tstPath: string): Promise<string>;
export declare function checkSslPath(): Promise<string>;
