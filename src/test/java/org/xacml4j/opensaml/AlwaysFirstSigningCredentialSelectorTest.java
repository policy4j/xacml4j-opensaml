package org.xacml4j.opensaml;

/*
 * #%L
 * XACML/OpenSAML Integration
 * %%
 * Copyright (C) 2009 - 2015 Xacml4J.org
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-3.0.html>.
 * #L%
 */

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.security.credential.Credential;

import com.google.common.collect.ImmutableList;

public class AlwaysFirstSigningCredentialSelectorTest {

	@Test
	public void testSelectCredential() throws Exception {
		AlwaysFirstSigningCredentialSelector selector = AlwaysFirstSigningCredentialSelector.instance();

		Credential cred1 = mock(Credential.class, "cred1");
		Credential cred2 = mock(Credential.class, "cred2");
		IDPConfiguration idpConfiguration = mock(IDPConfiguration.class);

		when(idpConfiguration.getSigningCredentials()).thenReturn(ImmutableList.of(cred1, cred2));

		Credential selectedCredential = selector.selectCredential(mock(RequestAbstractType.class),
            mock(Response.class), idpConfiguration);

		assertThat(selectedCredential, is(cred1));

        when(idpConfiguration.getSigningCredentials()).thenReturn(ImmutableList.of(cred2, cred1));

        selectedCredential = selector.selectCredential(mock(RequestAbstractType.class),
            mock(Response.class), idpConfiguration);

        assertThat(selectedCredential, is(cred2));
	}
}
