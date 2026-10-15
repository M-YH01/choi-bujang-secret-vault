import { opsApi } from '../../src/ops-api.mjs';

export default (request, response) => opsApi.handle(request, response);
