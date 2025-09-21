import { CertService } from '@techteamer/cert-utils';
interface TSA {
    C: string | null;
    L: string | null;
    O: string | null;
    OU: string | null;
    CN: string | null;
}
/**
 *
 * Status info:
 * Status: Granted.
 * Status description: unspecified
 * Failure info: unspecified
 *
 * TST info:
 * Version: 1
 * Policy OID: 1.3.6.1.4.1.21528.2.2.99
 * Hash Algorithm: sha256
 * Message data:
 * 0000 - c5 3e 94 56 aa 61 ed 56-49 69 74 29 1e 01 d7 2a   .>.V.a.VIit)...*
 * 0010 - 64 cc 24 84 d2 a2 31 4d-33 b6 ca c8 98 23 03 b9   d.$...1M3....#..
 * Serial number: 0x0308441E
 * Time stamp: Jan 30 13:45:20 2018 GMT
 * Accuracy: 0x01 seconds, unspecified millis, unspecified micros
 * Ordering: no
 * Nonce: unspecified
 * TSA: DirName:/C=HU/L=Budapest/O=Microsec Ltd./OU=e-Szigno CA/CN=e-Szigno Test TSA2
 * Extensions:
 * */
export declare class TimestampInfo {
    error: string | null;
    version: number | null;
    policyOID: string | null;
    hashAlgorithm: string | null;
    hash: string | null;
    serialNumber: string | null;
    timeStamp: Date | null;
    timeStampDate: Date | null;
    accuracy: number | null;
    ordering: boolean | null;
    nonce: string | null;
    issuer: string | null;
    tsa: TSA | null;
    certInfo: CertService['CertInfo'] | null;
    constructor(timestampInfoType: ("normal" | "short") | undefined, tsText: string, error?: string | null);
    setCertInfo(certInfo: CertService['CertInfo'] | null): void;
    parseOpensslOutput(tsText: string): void;
    parseOpensslOutputShort(tsText: string): void;
}
export {};
