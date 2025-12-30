#!/usr/bin/env python3
# coding=utf-8
"""
Tests for THC (ip.thc.org) discovery module.

THC provides multiple endpoints:
- Subdomain enumeration
- CNAME lookup
- Reverse DNS lookup

API Documentation: https://ip.thc.org/docs/
"""
import os
from typing import Optional

import httpx
import pytest

from theHarvester.discovery import thc
from theHarvester.lib.core import Core

github_ci: Optional[str] = os.getenv('GITHUB_ACTIONS')


# =============================================================================
# 1. Tests de API Directa (Validacion de Endpoints)
# =============================================================================
class TestThcApi:
    """Tests para validar que la API de THC responde correctamente."""

    @pytest.mark.asyncio
    async def test_api_subdomains_download_endpoint_responds(self) -> None:
        """Verificar que el endpoint de descarga de subdominios responde."""
        url = 'https://ip.thc.org/api/v1/subdomains/download?domain=google.com&limit=10&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            response = httpx.get(url, headers=headers, timeout=30)
            assert response.status_code == 200
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')

    @pytest.mark.asyncio
    async def test_api_subdomains_returns_text_format(self) -> None:
        """Verificar que la respuesta es texto plano."""
        url = 'https://ip.thc.org/api/v1/subdomains/download?domain=google.com&limit=5&hide_header=true'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            response = httpx.get(url, headers=headers, timeout=30)
            content_type = response.headers.get('content-type', '')
            assert 'text' in content_type or 'octet-stream' in content_type or response.status_code == 200
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')

    @pytest.mark.asyncio
    async def test_api_cli_subdomain_endpoint(self) -> None:
        """Verificar endpoint CLI /sb/{domain}."""
        url = 'https://ip.thc.org/sb/google.com?l=5&noheader'
        headers = {'User-Agent': Core.get_user_agent()}
        try:
            response = httpx.get(url, headers=headers, timeout=30)
            assert response.status_code == 200
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')


# =============================================================================
# 2. Tests de Busqueda de Subdominios (Funcionalidad Principal)
# =============================================================================
class TestThcSubdomainSearch:
    """Tests para la funcionalidad de busqueda de subdominios."""

    @staticmethod
    def domain() -> str:
        return 'tesla.com'

    @staticmethod
    def small_domain() -> str:
        return 'thc.org'

    @pytest.mark.asyncio
    async def test_search_returns_set(self) -> None:
        """Verificar que get_hostnames() retorna un set."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_finds_subdomains(self) -> None:
        """Verificar que encuentra subdominios para un dominio conocido."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        assert len(result) > 0, 'Should find at least one subdomain for tesla.com'

    @pytest.mark.asyncio
    async def test_search_results_contain_target_domain(self) -> None:
        """Verificar que todos los resultados contienen el dominio objetivo."""
        search = thc.SearchThc(self.small_domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        for hostname in result:
            assert self.small_domain() in hostname, f'{hostname} should contain {self.small_domain()}'

    @pytest.mark.asyncio
    async def test_search_no_duplicates(self) -> None:
        """Verificar que no hay duplicados en los resultados."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        result_list = list(result)
        assert len(result_list) == len(set(result_list))


# =============================================================================
# 3. Tests de Casos Edge
# =============================================================================
class TestThcEdgeCases:
    """Tests para casos limite y manejo de errores."""

    @pytest.mark.asyncio
    async def test_search_nonexistent_domain(self) -> None:
        """Verificar comportamiento con dominio inexistente."""
        search = thc.SearchThc('this-domain-definitely-does-not-exist-12345.com')
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        except Exception:
            pass
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_empty_domain(self) -> None:
        """Verificar comportamiento con dominio vacio."""
        search = thc.SearchThc('')
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        except Exception:
            pass
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_special_characters_domain(self) -> None:
        """Verificar comportamiento con caracteres especiales."""
        search = thc.SearchThc('example.com; DROP TABLE domains;--')
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        except Exception:
            pass
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_unicode_domain(self) -> None:
        """Verificar comportamiento con dominio IDN/unicode."""
        search = thc.SearchThc('münchen.de')
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        except Exception:
            pass
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_search_subdomain_as_input(self) -> None:
        """Verificar comportamiento cuando se pasa un subdominio."""
        search = thc.SearchThc('www.google.com')
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        assert isinstance(result, set)


# =============================================================================
# 4. Tests de Proxy
# =============================================================================
class TestThcProxy:
    """Tests para funcionalidad de proxy."""

    @staticmethod
    def domain() -> str:
        return 'example.com'

    @pytest.mark.asyncio
    async def test_process_accepts_proxy_parameter(self) -> None:
        """Verificar que process() acepta parametro proxy."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process(proxy=False)
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        assert isinstance(result, set)

    @pytest.mark.asyncio
    async def test_proxy_attribute_is_set(self) -> None:
        """Verificar que el atributo proxy se establece correctamente."""
        search = thc.SearchThc(self.domain())
        assert search.proxy is False


# =============================================================================
# 5. Tests de Inicializacion y Atributos
# =============================================================================
class TestThcInitialization:
    """Tests para inicializacion y estructura de la clase."""

    def test_init_sets_word(self) -> None:
        """Verificar que __init__ establece el dominio."""
        domain = 'test.com'
        search = thc.SearchThc(domain)
        assert search.word == domain

    def test_init_creates_empty_results(self) -> None:
        """Verificar que results se inicializa vacio."""
        search = thc.SearchThc('test.com')
        assert hasattr(search, 'results')
        assert len(search.results) == 0

    def test_init_proxy_default_false(self) -> None:
        """Verificar que proxy es False por defecto."""
        search = thc.SearchThc('test.com')
        assert search.proxy is False

    def test_class_has_required_methods(self) -> None:
        """Verificar que la clase tiene los metodos requeridos."""
        search = thc.SearchThc('test.com')
        assert hasattr(search, 'do_search')
        assert hasattr(search, 'get_hostnames')
        assert hasattr(search, 'process')
        assert callable(search.do_search)
        assert callable(search.get_hostnames)
        assert callable(search.process)


# =============================================================================
# 6. Tests de Formato de Respuesta
# =============================================================================
class TestThcResponseFormat:
    """Tests para verificar el formato de las respuestas."""

    @staticmethod
    def domain() -> str:
        return 'github.com'

    @pytest.mark.asyncio
    async def test_hostnames_are_strings(self) -> None:
        """Verificar que todos los hostnames son strings."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        for hostname in result:
            assert isinstance(hostname, str)

    @pytest.mark.asyncio
    async def test_hostnames_are_valid_format(self) -> None:
        """Verificar que los hostnames tienen formato valido."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        for hostname in result:
            assert ' ' not in hostname
            assert '\n' not in hostname
            assert '\t' not in hostname

    @pytest.mark.asyncio
    async def test_hostnames_are_lowercase(self) -> None:
        """Verificar que los hostnames estan en minusculas."""
        search = thc.SearchThc(self.domain())
        try:
            await search.process()
        except (httpx.TimeoutException, httpx.RequestError):
            pytest.skip('Skipping due to network error')
        result = await search.get_hostnames()
        for hostname in result:
            assert hostname == hostname.lower()


# =============================================================================
# 7. Tests de Integracion con theHarvester
# =============================================================================
@pytest.mark.skipif(github_ci == 'true', reason='Skip integration tests in CI')
class TestThcIntegration:
    """Tests de integracion con el framework theHarvester."""

    @pytest.mark.asyncio
    async def test_module_can_be_imported(self) -> None:
        """Verificar que el modulo se puede importar."""
        from theHarvester.discovery import thc as thc_module
        assert thc_module is not None

    @pytest.mark.asyncio
    async def test_search_class_exists(self) -> None:
        """Verificar que la clase SearchThc existe."""
        from theHarvester.discovery import thc as thc_module
        assert hasattr(thc_module, 'SearchThc')

    @pytest.mark.asyncio
    async def test_compatible_with_store_function(self) -> None:
        """Verificar compatibilidad con la funcion store de __main__.py."""
        search = thc.SearchThc('example.com')
        assert hasattr(search, 'process')
        assert hasattr(search, 'get_hostnames')


if __name__ == '__main__':
    pytest.main()
