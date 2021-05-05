import log from '@ajar/marker'
const { White,Reset,Red } = log.constants;
const { NODE_ENV } = process.env;

export const error_handler =  (err, req, res, next) => {
    log.cyan('error_handler','NODE_ENV:',NODE_ENV)
    log.error(err);
    if(NODE_ENV !== 'production')res.status(500).json({status:err.message,stack:err.stack});
    else res.status(500).json({status:'internal server error...'});
}
export const not_found =  (req, res) => {
    log.info(`url: ${White}${req.url}${Reset}${Red} not found...`);
    res.status(404).json({status:`url: ${req.url} not found...`});
}

