export interface VPData{
    vp_token: any;  // JSON object with VP related data
    _vp_token: any; // JSON object wit VP request related info
}


export interface SIOPTokensEcoded {
    id_token: string; // Base64 encoded JWT
    vp_token: string; // Base64 encoded JWT
}
