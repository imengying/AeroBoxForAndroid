use std::convert::TryFrom;

use crate::proto::{frame, varint::VarInt};

const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 64 * 1024;

/// Configures the HTTP/3 connection
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Config {
    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    pub(crate) send_grease: bool,

    #[cfg(test)]
    pub(crate) send_settings: bool,

    /// HTTP/3 Settings
    pub settings: Settings,
}

/// HTTP/3 Settings
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    pub(crate) qpack_max_table_capacity: u32,
    pub(crate) qpack_blocked_streams: u16,
    /// Maximum decoded field-section size, including the 32-byte overhead per field.
    pub(crate) max_field_section_size: u64,

    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub(crate) enable_webtransport: bool,
    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub(crate) enable_extended_connect: bool,
    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub(crate) enable_datagram: bool,
    /// The maximum number of concurrent streams that can be opened by the peer.
    pub(crate) max_webtransport_sessions: u64,
}

impl From<&frame::Settings> for Settings {
    fn from(settings: &frame::Settings) -> Self {
        Self::default().with_frame(settings)
    }
}

impl Settings {
    pub(crate) fn with_frame(self, settings: &frame::Settings) -> Self {
        Self {
            qpack_max_table_capacity: settings
                .get(frame::SettingId::QPACK_MAX_TABLE_CAPACITY)
                .map(|value| value.min(u32::MAX as u64) as u32)
                .unwrap_or(self.qpack_max_table_capacity),
            qpack_blocked_streams: settings
                .get(frame::SettingId::QPACK_MAX_BLOCKED_STREAMS)
                .map(|value| value.min(u16::MAX as u64) as u16)
                .unwrap_or(self.qpack_blocked_streams),
            max_field_section_size: settings
                .get(frame::SettingId::MAX_HEADER_LIST_SIZE)
                .unwrap_or(self.max_field_section_size),
            enable_webtransport: settings
                .get(frame::SettingId::ENABLE_WEBTRANSPORT)
                .map(|value| value != 0)
                .unwrap_or(self.enable_webtransport),
            max_webtransport_sessions: settings
                .get(frame::SettingId::WEBTRANSPORT_MAX_SESSIONS)
                .unwrap_or(self.max_webtransport_sessions),
            enable_datagram: settings
                .get(frame::SettingId::H3_DATAGRAM)
                .map(|value| value != 0)
                .unwrap_or(self.enable_datagram),
            enable_extended_connect: settings
                .get(frame::SettingId::ENABLE_CONNECT_PROTOCOL)
                .map(|value| value != 0)
                .unwrap_or(self.enable_extended_connect),
        }
    }
}

impl TryFrom<Config> for frame::Settings {
    type Error = frame::SettingsError;
    fn try_from(value: Config) -> Result<Self, Self::Error> {
        let mut settings = frame::Settings::default();

        let Config {
            send_grease,
            #[cfg(test)]
                send_settings: _,
            settings:
                Settings {
                    qpack_max_table_capacity,
                    qpack_blocked_streams,
                    max_field_section_size,
                    enable_webtransport,
                    enable_extended_connect,
                    enable_datagram,
                    max_webtransport_sessions,
                },
        } = value;

        if qpack_max_table_capacity != 0 {
            settings.insert(
                frame::SettingId::QPACK_MAX_TABLE_CAPACITY,
                qpack_max_table_capacity as u64,
            )?;
            settings.insert(
                frame::SettingId::QPACK_MAX_BLOCKED_STREAMS,
                qpack_blocked_streams as u64,
            )?;
        }

        if send_grease {
            //  Grease Settings (https://www.rfc-editor.org/rfc/rfc9114.html#name-defined-settings-parameters)
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers of the format 0x1f * N + 0x21 for non-negative
            //# integer values of N are reserved to exercise the requirement that
            //# unknown identifiers be ignored.  Such settings have no defined
            //# meaning.  Endpoints SHOULD include at least one such setting in their
            //# SETTINGS frame.

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers that were defined in [HTTP/2] where there is no
            //# corresponding HTTP/3 setting have also been reserved
            //# (Section 11.2.2).  These reserved settings MUST NOT be sent, and
            //# their receipt MUST be treated as a connection error of type
            //# H3_SETTINGS_ERROR.
            match settings.insert(frame::SettingId::grease(), 0) {
                Ok(_) => (),
                Err(_err) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("Error when adding the grease Setting. Reason {}", _err);
                }
            }
        }

        settings.insert(
            frame::SettingId::MAX_HEADER_LIST_SIZE,
            max_field_section_size,
        )?;
        settings.insert(
            frame::SettingId::ENABLE_CONNECT_PROTOCOL,
            enable_extended_connect as u64,
        )?;
        settings.insert(
            frame::SettingId::ENABLE_WEBTRANSPORT,
            enable_webtransport as u64,
        )?;
        settings.insert(frame::SettingId::H3_DATAGRAM, enable_datagram as u64)?;
        settings.insert(
            frame::SettingId::WEBTRANSPORT_MAX_SESSIONS,
            max_webtransport_sessions,
        )?;

        Ok(settings)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            max_field_section_size: VarInt::MAX.0,
            enable_webtransport: false,
            enable_extended_connect: false,
            enable_datagram: false,
            max_webtransport_sessions: 0,
        }
    }
}

impl Settings {
    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub fn enable_webtransport(&self) -> bool {
        self.enable_webtransport
    }

    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub fn enable_datagram(&self) -> bool {
        self.enable_datagram
    }

    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub fn enable_extended_connect(&self) -> bool {
        self.enable_extended_connect
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            send_grease: true,
            #[cfg(test)]
            send_settings: true,
            // Peer settings retain the RFC's unlimited initial value; local
            // receive limits must also keep the buffered-frame ceiling finite.
            settings: Settings {
                max_field_section_size: DEFAULT_MAX_FIELD_SECTION_SIZE,
                ..Settings::default()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_header_limit_is_finite_and_advertised() {
        let config = Config::default();
        assert_eq!(config.settings.max_field_section_size, 64 * 1024);
        let wire = frame::Settings::try_from(config).unwrap();
        assert_eq!(
            wire.get(frame::SettingId::MAX_HEADER_LIST_SIZE),
            Some(64 * 1024)
        );
    }

    #[test]
    fn omitted_peer_header_limit_remains_unlimited() {
        assert_eq!(Settings::default().max_field_section_size, VarInt::MAX.0);
        let peer = Settings::from(&frame::Settings::default());
        assert_eq!(peer.max_field_section_size, VarInt::MAX.0);
    }
}
